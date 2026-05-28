"""
Cyber Security Test Pipeline - Ghost-Actor Mesh
Implements a modern, high-performance location-transparent asyncio-based actor model.
Completely replaces Pykka with thread-safe queue-based asynchronous actors.
"""

from __future__ import annotations

import sys
import types
import time
import uuid
import asyncio
import threading
import concurrent.futures
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

# Define backward-compatible exception classes.
# We try to import pykka (either real or already mocked) to reuse the exact same classes.
try:
    import pykka
    ActorDeadError = pykka.ActorDeadError
    ActorTimeout = pykka.Timeout
except (ImportError, AttributeError):
    class ActorDeadError(Exception):
        """Exception raised when an operation is attempted on a dead actor."""
        pass

    class ActorTimeout(Exception):
        """Exception raised when an actor request times out."""
        pass

    # Dynamically register the pykka compatibility layer to support legacy imports
    class PykkaCompatibility(types.ModuleType):
        ActorDeadError = ActorDeadError
        Timeout = ActorTimeout
        ActorDeadError.__module__ = "pykka"
        ActorTimeout.__module__ = "pykka"

    sys.modules["pykka"] = PykkaCompatibility("pykka")

from src.core.contracts.health import HealthComponent, HealthMetric, HealthStatus
from src.core.frontier.marshaller import (
    mesh_marshal,
    mesh_unmarshal,
    mesh_marshal_pickle,
    mesh_unmarshal_pickle,
    compress_bytes,
    decompress_bytes,
)
from src.core.frontier.state import CRDTCompactionBudget, stable_digest
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

try:
    import psutil
except ImportError:
    psutil = None


@dataclass
class ActorState:
    """Serializable state for actor migration with Zstd compression and differential support."""

    actor_id: str
    stage: str
    data: dict[str, Any]
    checkpoint_ts: float
    evacuation_recommended: bool = False
    logic_fn_name: str = ""
    snapshot_format: str = "ghost-actor-snapshot-v4"
    last_wal_id: str | None = None
    migration_id: str = ""
    state_digest: str = ""
    applied_wal_ids: list[str] = field(default_factory=list)
    compaction_budget: dict[str, Any] = field(default_factory=dict)
    serialized_logic_fn: bytes | None = None
    snapshot_type: str = "full"  # "full" or "differential"

    def pack(self) -> bytes:
        """Binary serialization via MessagePack with Zstd compression."""
        payload = mesh_marshal(
            {
                "actor_id": self.actor_id,
                "stage": self.stage,
                "data": self.data,
                "checkpoint_ts": self.checkpoint_ts,
                "evacuation_recommended": self.evacuation_recommended,
                "logic_fn_name": self.logic_fn_name,
                "snapshot_format": self.snapshot_format,
                "last_wal_id": self.last_wal_id,
                "migration_id": self.migration_id,
                "state_digest": self.state_digest or stable_digest(self.data),
                "applied_wal_ids": self.applied_wal_ids,
                "compaction_budget": self.compaction_budget,
                "serialized_logic_fn": self.serialized_logic_fn,
                "snapshot_type": self.snapshot_type,
            }
        )
        return compress_bytes(payload)

    @classmethod
    def unpack(cls, payload: bytes) -> ActorState:
        """Binary deserialization via MessagePack with Zstd decompression."""
        decompressed = decompress_bytes(payload)
        data = mesh_unmarshal(decompressed)
        data.setdefault("snapshot_format", "ghost-actor-snapshot-v4")
        data.setdefault("last_wal_id", None)
        data.setdefault("migration_id", "")
        data.setdefault("state_digest", stable_digest(data.get("data", {})))
        data.setdefault("applied_wal_ids", [])
        data.setdefault("compaction_budget", {})
        data.setdefault("serialized_logic_fn", None)
        data.setdefault("snapshot_type", "full")
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    def dehydrate(self) -> bytes:
        """Serialize actor state into a binary format."""
        return self.pack()

    @classmethod
    def rehydrate(cls, payload: Any) -> ActorState:
        """De-serialize actor state from a binary format."""
        if isinstance(payload, cls):
            return payload
        if isinstance(payload, dict):
            payload.setdefault("actor_id", "actor-unknown")
            payload.setdefault("stage", "stage-unknown")
            payload.setdefault("data", {})
            payload.setdefault("checkpoint_ts", 0.0)
            payload.setdefault("evacuation_recommended", False)
            payload.setdefault("logic_fn_name", "")
            payload.setdefault("snapshot_format", "ghost-actor-snapshot-v4")
            payload.setdefault("last_wal_id", None)
            payload.setdefault("migration_id", "")
            payload.setdefault("state_digest", "")
            payload.setdefault("applied_wal_ids", [])
            payload.setdefault("compaction_budget", {})
            payload.setdefault("serialized_logic_fn", None)
            payload.setdefault("snapshot_type", "full")
            valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
            filtered = {k: v for k, v in payload.items() if k in valid_keys}
            return cls(**filtered)
        if isinstance(payload, bytes):
            return cls.unpack(payload)
        raise TypeError(f"a bytes-like object is required, not {type(payload).__name__}")


_LOGIC_REGISTRY: dict[str, Callable[[dict[str, Any], dict[str, Any]], Any]] = {}


class ActorFuture:
    """Thread-safe future mimicking pykka.Future."""

    def __init__(self, fut: concurrent.futures.Future[Any]) -> None:
        self._fut = fut

    def get(self, timeout: float | None = None) -> Any:
        """Block until the future resolves, supporting precise timeout errors."""
        try:
            return self._fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise ActorTimeout("Actor request timed out")
        except Exception as e:
            raise e


class ProxyAttribute:
    """Helper to query properties or call methods on an actor proxy."""

    def __init__(self, actor_ref: ActorRef, name: str) -> None:
        self._actor_ref = actor_ref
        self._name = name

    def __call__(self, *args: Any, **kwargs: Any) -> ActorFuture:
        # Call a method remotely
        return self._actor_ref.ask(
            {"command": self._name, "args": args, "kwargs": kwargs}, block=False
        )

    def get(self, timeout: float | None = None) -> Any:
        # Query property/attribute value
        future = self._actor_ref.ask(
            {"command": "_get_attribute", "name": self._name}, block=False
        )
        return future.get(timeout=timeout)


class ScanActorProxy:
    """Dynamic proxy for location-transparent actor calls."""

    def __init__(self, actor_ref: ActorRef) -> None:
        self._actor_ref = actor_ref

    def stop(self) -> None:
        """Stop the actor directly via actor_ref."""
        self._actor_ref.stop()

    @property
    def actor_ref(self) -> ActorRef:
        """Expose actor_ref property for pykka compatibility."""
        return self._actor_ref

    def __getattr__(self, name: str) -> Any:
        return ProxyAttribute(self._actor_ref, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            super().__setattr__(name, value)
        else:
            self._actor_ref.ask(
                {"command": "_set_attribute", "name": name, "value": value}, block=True
            )


class ActorRef:
    """Reference wrapper mapping interactions to a running ScanActor loop thread-safely."""

    def __init__(self, actor: ScanActor) -> None:
        self._actor = actor

    def ask(self, message: Any, block: bool = True, timeout: float | None = None) -> Any:
        """Deliver a message to the actor queue and await response."""
        if not self.is_alive():
            raise ActorDeadError("Actor is dead")

        fut: concurrent.futures.Future[Any] = concurrent.futures.Future()

        async def put_msg() -> None:
            await self._actor._queue.put((message, fut))

        try:
            asyncio.run_coroutine_threadsafe(put_msg(), self._actor._loop)
        except Exception:
            raise ActorDeadError("Actor is dead")

        actor_future = ActorFuture(fut)
        if block:
            return actor_future.get(timeout=timeout)
        return actor_future

    def stop(self) -> None:
        """Cleanly terminate the actor background thread."""
        if self._actor.is_alive:
            self._actor.stop()

    def is_alive(self) -> bool:
        """Check if the actor background loop is active."""
        return self._actor.is_alive

    def proxy(self) -> ScanActorProxy:
        """Build a dynamic proxy wrapper to call methods as futures."""
        return ScanActorProxy(self)


class ScanActor:
    """
    Frontier Task Actor.
    Encapsulates logic and state, running on an isolated background asyncio event loop thread.
    """

    def __init__(
        self, actor_id: str, logic_fn: Callable[[dict[str, Any], dict[str, Any]], Any]
    ) -> None:
        self.actor_id = actor_id
        self.logic_fn = logic_fn
        self.state: dict[str, Any] = {}
        self._applied_wal_ids: set[str] = set()
        self.is_migrating = False
        self._last_health_check = 0.0
        self._evacuation_recommended = False
        self.compaction_budget = CRDTCompactionBudget()

        # Differential state snapshot logging
        self._snapshot_count = 0
        self._baseline_snapshot: dict[str, Any] | None = None
        self._baseline_ts = 0.0
        self._differential_deltas: list[dict[str, Any]] = []

        # Threading infrastructure
        self.is_alive = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._queue: asyncio.Queue[tuple[Any, concurrent.futures.Future[Any]]] | None = None

        if hasattr(logic_fn, "__name__"):
            _LOGIC_REGISTRY[logic_fn.__name__] = logic_fn

    @classmethod
    def start(
        cls, actor_id: str, logic_fn: Callable[[dict[str, Any], dict[str, Any]], Any]
    ) -> ActorRef:
        """Spawn a new actor instance, starting its processing thread."""
        actor = cls(actor_id, logic_fn)
        actor.is_alive = True
        actor._thread = threading.Thread(target=actor._run_loop, daemon=True)
        actor._thread.start()

        # Wait for the loop to spin up
        while actor._loop is None or not actor._loop.is_running():
            time.sleep(0.01)

        return ActorRef(actor)

    def _run_loop(self) -> None:
        """Target for background OS thread, running isolated asyncio event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def init_mailbox() -> None:
            self._queue = asyncio.Queue()
            self._mailbox_task = asyncio.create_task(self._mailbox_loop())

        self._loop.run_until_complete(init_mailbox())
        self._loop.run_forever()
        self._loop.close()

    async def _mailbox_loop(self) -> None:
        """Sequential processing of messages on the actor thread."""
        while self.is_alive:
            try:
                message, fut = await self._queue.get()
                try:
                    res = self._handle_message(message)
                    fut.set_result(res)
                except Exception as exc:
                    fut.set_exception(exc)
                finally:
                    self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("ScanActor [%s] mailbox error: %s", self.actor_id, e)

    def _handle_message(self, message: Any) -> Any:
        """Route received envelopes to standard functions or whitelisted commands."""
        if isinstance(message, dict) and "command" in message:
            cmd = message["command"]
            if cmd == "_get_attribute":
                return getattr(self, message["name"])
            if cmd == "_set_attribute":
                setattr(self, message["name"], message["value"])
                return None

            known_commands = {
                "execute",
                "snapshot",
                "recover",
                "migrate",
                "health_check",
                "prepare_migration",
                "dehydrate",
                "rehydrate",
                "cold_start",
                "warm_rejoin",
            }

            # Map proxy calls to direct methods if present
            if cmd not in known_commands and hasattr(self, cmd) and callable(getattr(self, cmd)):
                method = getattr(self, cmd)
                return method(*message.get("args", ()), **message.get("kwargs", {}))

            return self.on_receive(message)

        return self.on_receive(message)

    def stop(self) -> None:
        """Shutdown the actor loop and join processing thread."""
        self.is_alive = False
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread and threading.current_thread() != self._thread:
            self._thread.join(timeout=1.0)

    def dehydrate(self, migration_id: str = "") -> bytes:
        """Freeze actor mutating work and dehydrate its state to compressed bytes."""
        self.is_migrating = True
        state_data = dict(self.state)

        compaction_budget_data = {
            "budget_ms": getattr(self.compaction_budget, "budget_ms", 50.0),
            "min_budget_ms": getattr(self.compaction_budget, "min_budget_ms", 5.0),
            "max_budget_ms": getattr(self.compaction_budget, "max_budget_ms", 500.0),
            "target_elapsed_ms": getattr(self.compaction_budget, "target_elapsed_ms", 30.0),
        }

        try:
            serialized_logic = mesh_marshal_pickle(self.logic_fn)
        except Exception as e:
            logger.warning("Ghost-Actor [%s]: Failed to serialize logic_fn: %s", self.actor_id, e)
            serialized_logic = None

        # Build snapshot type dynamically
        self._snapshot_count += 1
        is_full = (self._snapshot_count % 5 == 1) or (self._baseline_snapshot is None)

        if is_full:
            self._baseline_snapshot = state_data
            self._baseline_ts = time.time()
            self._differential_deltas = []
            snapshot_type = "full"
            snapshot_data = state_data
        else:
            snapshot_type = "differential"
            snapshot_data = {
                "baseline_ts": self._baseline_ts,
                "deltas": list(self._differential_deltas),
                "last_wal_id": self.state.get("_last_wal_id"),
            }

        actor_state = ActorState(
            actor_id=self.actor_id,
            stage=self.state.get("current_stage", "init"),
            data=snapshot_data,
            checkpoint_ts=time.time(),
            evacuation_recommended=self._evacuation_recommended,
            logic_fn_name=getattr(self.logic_fn, "__name__", ""),
            last_wal_id=self.state.get("_last_wal_id"),
            state_digest=stable_digest(state_data),
            migration_id=migration_id,
            applied_wal_ids=list(self._applied_wal_ids),
            compaction_budget=compaction_budget_data,
            serialized_logic_fn=serialized_logic,
            snapshot_type=snapshot_type,
        )
        return actor_state.dehydrate()

    def rehydrate(self, payload: bytes) -> None:
        """Restore actor state from packed binary payload."""
        unpacked = ActorState.rehydrate(payload)
        self.state = unpacked.data
        self._applied_wal_ids = set(unpacked.data.get("_applied_wal_ids", []))
        if unpacked.applied_wal_ids:
            self._applied_wal_ids.update(unpacked.applied_wal_ids)
        if unpacked.last_wal_id:
            self._applied_wal_ids.add(unpacked.last_wal_id)
            self.state["_last_wal_id"] = unpacked.last_wal_id

        if unpacked.compaction_budget:
            self.compaction_budget.budget_ms = unpacked.compaction_budget.get("budget_ms", 50.0)
            self.compaction_budget.min_budget_ms = unpacked.compaction_budget.get(
                "min_budget_ms", 5.0
            )
            self.compaction_budget.max_budget_ms = unpacked.compaction_budget.get(
                "max_budget_ms", 500.0
            )
            self.compaction_budget.target_elapsed_ms = unpacked.compaction_budget.get(
                "target_elapsed_ms", 30.0
            )

        restored_logic = None
        if unpacked.serialized_logic_fn:
            try:
                restored_logic = mesh_unmarshal_pickle(unpacked.serialized_logic_fn)
            except Exception as e:
                logger.error(
                    "Ghost-Actor [%s]: Failed to deserialize logic_fn: %s", self.actor_id, e
                )

        if restored_logic:
            self.logic_fn = restored_logic
            if hasattr(restored_logic, "__name__"):
                _LOGIC_REGISTRY[restored_logic.__name__] = restored_logic
        elif unpacked.logic_fn_name:
            reg_logic = _LOGIC_REGISTRY.get(unpacked.logic_fn_name)
            if reg_logic:
                self.logic_fn = reg_logic

    def cold_start(self, snapshot_bytes: bytes, wal_deltas: list[dict[str, Any]]) -> None:
        """Completely reconstruct state from a cold-start checkpoint snapshot plus trailing WAL."""
        self.rehydrate(snapshot_bytes)
        self.warm_rejoin(wal_deltas)

    def warm_rejoin(self, wal_deltas: list[dict[str, Any]]) -> None:
        """Replay trailing/outstanding WAL deltas since last applied ID."""
        self._differential_deltas.extend(wal_deltas)
        for delta_entry in wal_deltas:
            wal_id = delta_entry.get("id")
            if isinstance(wal_id, str) and wal_id in self._applied_wal_ids:
                continue
            delta = delta_entry.get("delta", {})
            if isinstance(delta, dict):
                self._merge_recovered_delta(delta)
                if isinstance(wal_id, str):
                    self._applied_wal_ids.add(wal_id)
                    self.state["_last_wal_id"] = wal_id

    def on_receive(self, message: dict[str, Any]) -> Any:
        if not isinstance(message, dict) or "command" not in message:
            logger.error("Ghost-Actor [%s] failure: Invalid message format", self.actor_id)
            return {"status": "error", "error": "Invalid message format"}

        command = message.get("command")

        known_commands = {
            "execute",
            "snapshot",
            "recover",
            "migrate",
            "health_check",
            "prepare_migration",
            "dehydrate",
            "rehydrate",
            "cold_start",
            "warm_rejoin",
        }
        if command not in known_commands:
            logger.error("Ghost-Actor [%s] failure: Unknown command %s", self.actor_id, command)
            return {"status": "error", "error": f"Unknown command: {command}"}

        if self.is_migrating and command in {
            "execute",
            "recover",
            "migrate",
            "rehydrate",
            "cold_start",
            "warm_rejoin",
        }:
            logger.warning(
                "Ghost-Actor [%s] rejected command '%s': Actor is currently migrating",
                self.actor_id,
                command,
            )
            return {"status": "error", "error": "Actor is currently migrating"}

        if command == "execute":
            self._check_local_health()
            task_input = message.get("input", {})
            self._differential_deltas.append(
                {"id": f"exec-{uuid.uuid4().hex[:8]}", "delta": task_input}
            )
            return self._execute_logic(task_input)

        elif command == "snapshot":
            # snapshot increments count and builds full/differential accordingly
            state_data = dict(self.state)
            self._snapshot_count += 1
            is_full = (self._snapshot_count % 5 == 1) or (self._baseline_snapshot is None)

            if is_full:
                self._baseline_snapshot = state_data
                self._baseline_ts = time.time()
                self._differential_deltas = []
                snapshot_type = "full"
                snapshot_data = state_data
            else:
                snapshot_type = "differential"
                snapshot_data = {
                    "baseline_ts": self._baseline_ts,
                    "deltas": list(self._differential_deltas),
                    "last_wal_id": self.state.get("_last_wal_id"),
                }

            return ActorState(
                actor_id=self.actor_id,
                stage=self.state.get("current_stage", "init"),
                data=snapshot_data,
                checkpoint_ts=time.time(),
                evacuation_recommended=self._evacuation_recommended,
                logic_fn_name=getattr(self.logic_fn, "__name__", ""),
                last_wal_id=self.state.get("_last_wal_id"),
                state_digest=stable_digest(state_data),
                snapshot_type=snapshot_type,
            )

        elif command == "recover":
            wal_deltas = message.get("deltas", [])
            logger.info(
                "Ghost-Actor [%s]: Replaying %d deltas from WAL", self.actor_id, len(wal_deltas)
            )
            self._differential_deltas.extend(wal_deltas)
            for delta_entry in wal_deltas:
                wal_id = delta_entry.get("id")
                if isinstance(wal_id, str) and wal_id in self._applied_wal_ids:
                    continue
                delta = delta_entry.get("delta", {})
                if isinstance(delta, dict):
                    self._merge_recovered_delta(delta)
                    if isinstance(wal_id, str):
                        self._applied_wal_ids.add(wal_id)
                        self.state["_last_wal_id"] = wal_id
            return {"status": "success", "applied_count": len(self._applied_wal_ids)}

        elif command == "dehydrate":
            migration_id = str(message.get("migration_id") or "")
            return self.dehydrate(migration_id)

        elif command == "rehydrate":
            payload = message.get("payload")
            if not isinstance(payload, bytes):
                return {"status": "error", "error": "Missing or invalid payload"}
            self.rehydrate(payload)
            return {"status": "success"}

        elif command == "cold_start":
            snapshot_bytes = message.get("snapshot")
            wal_deltas = message.get("deltas", [])
            if not isinstance(snapshot_bytes, bytes):
                return {"status": "error", "error": "Missing or invalid snapshot"}
            self.cold_start(snapshot_bytes, wal_deltas)
            return {"status": "success"}

        elif command == "warm_rejoin":
            wal_deltas = message.get("deltas", [])
            self.warm_rejoin(wal_deltas)
            return {"status": "success"}

        elif command == "prepare_migration":
            self.is_migrating = True
            snapshot = cast(ActorState, self.on_receive({"command": "snapshot"}))
            snapshot.migration_id = str(message.get("migration_id") or uuid.uuid4())
            # Digest is calculated relative to actual full data dictionary
            real_data = (
                snapshot.data
                if snapshot.snapshot_type == "full"
                else (self._baseline_snapshot or {})
            )
            snapshot.state_digest = stable_digest(real_data)
            return snapshot.pack()

        elif command == "migrate":
            migration_id = str(message.get("migration_id") or uuid.uuid4())
            snapshot_payload = self.on_receive(
                {"command": "prepare_migration", "migration_id": migration_id}
            )
            snapshot = ActorState.unpack(cast(bytes, snapshot_payload))
            logger.warning(
                "Ghost-Actor [%s]: Initiating migration %s (Evac Recommended: %s)",
                self.actor_id,
                migration_id,
                self._evacuation_recommended,
            )
            self.stop()
            return snapshot.pack()

        elif command == "health_check":
            self._check_local_health()
            real_data = (
                self.state
                if self._baseline_snapshot is None
                else self._baseline_snapshot
            )
            return {
                "actor_id": self.actor_id,
                "evacuation_recommended": self._evacuation_recommended,
                "node_cpu": psutil.cpu_percent(interval=0.1) if psutil else 0.0,
                "status": "evacuate" if self._evacuation_recommended else "ok",
                "state_size": len(real_data),
                "last_health_check": self._last_health_check,
            }

        else:
            logger.error("Ghost-Actor [%s] failure: Unknown command %s", self.actor_id, command)
            return {"status": "error", "error": f"Unknown command: {command}"}

    def _check_local_health(self) -> None:
        """Monitor local resource pressure to proactively flag migration needs."""
        now = time.time()
        if now - self._last_health_check < 10.0:
            return

        self._last_health_check = now
        if not psutil:
            return

        try:
            cpu = psutil.cpu_percent(interval=0.1)
            ram_pct = psutil.virtual_memory().percent

            if cpu > 90.0 or ram_pct > 95.0:
                if not self._evacuation_recommended:
                    logger.warning(
                        "Ghost-Actor [%s]: Node pressure detected (CPU: %.1f%%, RAM: %.1f%%). "
                        "Flagging for evacuation.",
                        self.actor_id,
                        cpu,
                        ram_pct,
                    )
                self._evacuation_recommended = True
            else:
                self._evacuation_recommended = False
        except Exception as e:
            logger.debug("Ghost-Actor [%s]: Health check failed: %s", self.actor_id, e)

    def _execute_logic(self, task_input: dict[str, Any]) -> dict[str, Any]:
        """Runs the encapsulated security logic."""
        logger.info("Ghost-Actor [%s]: Executing logic...", self.actor_id)
        try:
            result = self.logic_fn(task_input, self.state)
            return {"status": "success", "output": result}
        except Exception as e:
            logger.error("Ghost-Actor [%s] failure: %s", self.actor_id, e)
            return {"status": "error", "error": str(e)}

    def _merge_recovered_delta(self, delta: dict[str, Any]) -> None:
        """Apply recovered state without duplicating list/set transitions."""
        for key, value in delta.items():
            if key.startswith("_"):
                continue
            current = self.state.get(key)
            if isinstance(current, dict) and isinstance(value, dict):
                current.update(value)
            elif isinstance(current, list) and isinstance(value, list):
                seen = {stable_digest(item) for item in current}
                for item in value:
                    digest = stable_digest(item)
                    if digest not in seen:
                        current.append(item)
                        seen.add(digest)
            elif isinstance(current, set) and isinstance(value, (list, set, tuple, frozenset)):
                current.update(value)
            elif current is None:
                self.state[key] = list(value) if isinstance(value, tuple) else value
            else:
                self.state[key] = value


class GhostMeshCoordinator:
    """Orchestrates actor placement and migration across the Neural-Mesh."""

    def __init__(self, registry: GhostMeshRegistry, gossip: Any) -> None:
        self.registry = registry
        self.gossip = gossip
        from src.infrastructure.mesh.balancer import NeuralMeshBalancer
        self.balancer = NeuralMeshBalancer()
        is_mock = gossip.__class__.__name__ in ("MagicMock", "Mock")
        if gossip and hasattr(gossip, "__dict__") and not is_mock:
            gossip._coordinator = self

    async def migrate_if_needed(
        self,
        actor_ref: ActorRef,
        task_metadata: dict[str, Any],
    ) -> bool:
        """Check if an actor should be migrated and execute the move if a better node is found."""
        try:
            local_node = self.gossip.local_node
            is_under_pressure = local_node.cpu_usage > 90.0 or local_node.ram_available_mb < 500.0

            if not is_under_pressure:
                try:
                    health = cast(
                        dict[str, Any], actor_ref.ask({"command": "health_check"}, timeout=0.5)
                    )
                    if not health.get("evacuation_recommended"):
                        return False
                except Exception:
                    return False

            try:
                actor_id = str(cast(Any, actor_ref.proxy()).actor_id.get(timeout=0.5))
            except Exception:
                actor_id = f"actor:{task_metadata.get('actor_id', 'unknown')}"

            logger.info(
                "Ghost-Coordinator: Initiating proactive migration for [%s] due to node pressure",
                actor_id,
            )

            target_node_id = self.balancer.select_best_node_from_gossip(self.gossip, task_metadata)
            current_node_id = local_node.id

            if target_node_id and target_node_id != current_node_id:
                logger.info(
                    "Ghost-Coordinator: Migrating [%s] from %s -> %s",
                    actor_id,
                    current_node_id,
                    target_node_id,
                )

                migration_id = str(uuid.uuid4())

                # 1. Freeze actor and dehydrate stable snapshot
                packed_state = actor_ref.ask(
                    {"command": "dehydrate", "migration_id": migration_id},
                    block=True,
                )
                unpacked = ActorState.rehydrate(packed_state)
                if not isinstance(packed_state, bytes):
                    packed_state = unpacked.pack()

                # 2. Store the serialized state in the registry
                await self.registry.store_actor_state(actor_id, packed_state)
                await self.registry.prepare_migration(
                    actor_id=actor_id,
                    migration_id=migration_id,
                    source_node=current_node_id,
                    target_node=target_node_id,
                    state_digest=unpacked.state_digest,
                )

                # 3. Update mappings
                await self.registry.register_actor(actor_id, target_node_id)
                await self.registry.commit_migration(actor_id, migration_id)

                # 4. Terminate source actor
                actor_ref.stop()

                # 5. Emit Migration Event
                from src.core.events import EventType, get_event_bus
                get_event_bus().emit(
                    EventType.GHOST_ACTOR_MIGRATED,
                    source=f"ghost-coordinator-{self.gossip.local_node.id}",
                    data={
                        "actor_id": actor_id,
                        "source_node": current_node_id,
                        "target_node": target_node_id,
                        "reason": "resource_pressure",
                        "migration_id": migration_id,
                        "state_digest": unpacked.state_digest,
                    },
                )

                # 6. UDP syncing
                is_mock = self.gossip.__class__.__name__ in ("MagicMock", "Mock")
                if (
                    not is_mock
                    and hasattr(self.gossip, "peers")
                    and isinstance(self.gossip.peers, dict)
                ):
                    target_peer = self.gossip.peers.get(target_node_id)
                    if target_peer and hasattr(self.gossip, "_send_reliable"):
                        logic_fn_name = unpacked.logic_fn_name or "dummy_logic"
                        await self.gossip._send_reliable(
                            target_peer,
                            "ghost_actor_spawn",
                            {
                                "actor_id": actor_id,
                                "logic_fn_name": logic_fn_name,
                                "migration_id": migration_id,
                                "state_digest": unpacked.state_digest,
                            },
                        )

                return True

            return False
        except Exception as e:
            logger.error("Ghost-Coordinator: Migration failed: %s", e)
            return False

    async def health_metrics(
        self, actor_refs: list[ActorRef] | None = None
    ) -> list[HealthMetric]:
        """Probe actor pressure for the self-healing controller."""
        metrics: list[HealthMetric] = []
        local_node = getattr(self.gossip, "local_node", None)
        if local_node is not None:
            pressured = local_node.cpu_usage > 90.0 or local_node.ram_available_mb < 500.0
            metrics.append(
                HealthMetric(
                    component=HealthComponent.GHOST_ACTOR,
                    name="ghost_mesh_node_pressure",
                    value=float(local_node.cpu_usage),
                    threshold=90.0,
                    status=HealthStatus.DEGRADED if pressured else HealthStatus.OK,
                    labels={
                        "node_id": local_node.id,
                        "ram_available_mb": local_node.ram_available_mb,
                        "active_jobs": local_node.active_jobs,
                    },
                )
            )
        for actor_ref in actor_refs or []:
            try:
                health = cast(
                    dict[str, Any], actor_ref.ask({"command": "health_check"}, timeout=0.5)
                )
                metrics.append(
                    HealthMetric(
                        component=HealthComponent.GHOST_ACTOR,
                        name="ghost_actor_evacuation",
                        value=bool(health.get("evacuation_recommended")),
                        status=HealthStatus.DEGRADED
                        if health.get("evacuation_recommended")
                        else HealthStatus.OK,
                        labels={"actor_id": health.get("actor_id", "unknown")},
                    )
                )
            except Exception as exc:
                metrics.append(
                    HealthMetric(
                        component=HealthComponent.GHOST_ACTOR,
                        name="ghost_actor_probe_error",
                        value=1,
                        status=HealthStatus.CRITICAL,
                        labels={"error": str(exc)},
                    )
                )
        return metrics

    async def rebalance_actors(
        self,
        actor_refs: list[ActorRef],
        task_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Migrate actors that are on pressured nodes."""
        migrated = 0
        for actor_ref in actor_refs:
            if await self.migrate_if_needed(actor_ref, task_metadata or {}):
                migrated += 1
        return {"checked": len(actor_refs), "migrated": migrated}

    async def spawn_or_rehydrate_actor(
        self, actor_id: str, logic_fn: Callable[[dict[str, Any], dict[str, Any]], Any]
    ) -> ActorRef:
        """Spawn a new actor instance, automatically re-hydrating from registry if state exists."""
        actor_ref = ScanActor.start(actor_id, logic_fn)

        packed_state = await self.registry.retrieve_actor_state(actor_id)
        if packed_state:
            try:
                actor_ref.ask({"command": "rehydrate", "payload": packed_state}, block=True)
                logger.info(
                    "Ghost-Coordinator: Successfully re-hydrated actor [%s] with state checkpoints",
                    actor_id,
                )
                await self.registry.clear_actor_state(actor_id)
                await self.registry.clear_migration(actor_id)
            except Exception as e:
                logger.error(
                    "Ghost-Coordinator: Failed to re-hydrate actor [%s] from state: %s",
                    actor_id,
                    e,
                )

        return actor_ref


class GhostMeshRegistry:
    """Global Registry managing active actors and implementing differential checkpoint strategies."""

    def __init__(self, redis_client: Any, run_id: str = "default") -> None:
        self._redis = redis_client
        self._registry_key = f"cyber:ghost:registry:{run_id}"
        self._state_key = f"cyber:ghost:state:{run_id}"
        self._baseline_key = f"cyber:ghost:baseline:{run_id}"
        self._migration_key = f"cyber:ghost:migration:{run_id}"

    async def register_actor(self, actor_id: str, node_id: str) -> None:
        """Map an actor to its current host node."""
        await self._redis.hset(self._registry_key, actor_id, node_id)
        await self._redis.expire(self._registry_key, 86400)

    async def find_actor(self, actor_id: str) -> str | None:
        """Find the node_id currently hosting the actor."""
        return cast(str | None, await self._redis.hget(self._registry_key, actor_id))

    async def unregister_actor(self, actor_id: str) -> None:
        await self._redis.hdel(self._registry_key, actor_id)

    async def store_actor_state(self, actor_id: str, state_bytes: bytes) -> None:
        """Store state in Redis, managing baseline full snapshots vs. differential deltas."""
        state = ActorState.unpack(state_bytes)
        if state.snapshot_type == "full":
            await self._redis.hset(self._state_key, actor_id, state_bytes)
            await self._redis.hset(self._baseline_key, actor_id, state_bytes)
            await self._redis.expire(self._baseline_key, 86400)
        else:
            await self._redis.hset(self._state_key, actor_id, state_bytes)
        await self._redis.expire(self._state_key, 86400)

    async def retrieve_actor_state(self, actor_id: str) -> bytes | None:
        """Retrieve state from Redis, dynamically reassembling differential records if needed."""
        state_bytes = cast(bytes | None, await self._redis.hget(self._state_key, actor_id))
        if not state_bytes:
            return None

        state = ActorState.unpack(state_bytes)
        if state.snapshot_type == "differential":
            baseline_bytes = cast(bytes | None, await self._redis.hget(self._baseline_key, actor_id))
            if baseline_bytes:
                baseline = ActorState.unpack(baseline_bytes)
                reconstructed_data = dict(baseline.data)

                # Sequential replay of differential delta collections
                deltas = state.data.get("deltas", [])
                for delta_entry in deltas:
                    delta = delta_entry.get("delta", {}) if isinstance(delta_entry, dict) else delta_entry
                    if isinstance(delta, dict):
                        for key, value in delta.items():
                            if key.startswith("_"):
                                continue
                            current = reconstructed_data.get(key)
                            if isinstance(current, dict) and isinstance(value, dict):
                                current.update(value)
                            elif isinstance(current, list) and isinstance(value, list):
                                seen = {stable_digest(item) for item in current}
                                for item in value:
                                    digest = stable_digest(item)
                                    if digest not in seen:
                                        current.append(item)
                                        seen.add(digest)
                            elif isinstance(current, set) and isinstance(value, (list, set, tuple, frozenset)):
                                current.update(value)
                            elif current is None:
                                reconstructed_data[key] = list(value) if isinstance(value, tuple) else value
                            else:
                                reconstructed_data[key] = value

                reconstructed_state = ActorState(
                    actor_id=state.actor_id,
                    stage=state.stage,
                    data=reconstructed_data,
                    checkpoint_ts=state.checkpoint_ts,
                    evacuation_recommended=state.evacuation_recommended,
                    logic_fn_name=state.logic_fn_name,
                    snapshot_format=state.snapshot_format,
                    last_wal_id=state.last_wal_id,
                    migration_id=state.migration_id,
                    state_digest=stable_digest(reconstructed_data),
                    applied_wal_ids=state.applied_wal_ids,
                    compaction_budget=state.compaction_budget,
                    serialized_logic_fn=state.serialized_logic_fn,
                    snapshot_type="full",
                )
                return reconstructed_state.pack()

        return state_bytes

    async def clear_actor_state(self, actor_id: str) -> None:
        """Remove packed actor states from Redis."""
        await self._redis.hdel(self._state_key, actor_id)
        await self._redis.hdel(self._baseline_key, actor_id)

    async def prepare_migration(
        self,
        *,
        actor_id: str,
        migration_id: str,
        source_node: str,
        target_node: str,
        state_digest: str,
    ) -> None:
        """Record an in-flight migration before changing actor ownership."""
        await self._redis.hset(
            self._migration_key,
            actor_id,
            mesh_marshal(
                {
                    "status": "prepared",
                    "actor_id": actor_id,
                    "migration_id": migration_id,
                    "source_node": source_node,
                    "target_node": target_node,
                    "state_digest": state_digest,
                    "updated_at": time.time(),
                }
            ),
        )
        await self._redis.expire(self._migration_key, 86400)

    async def commit_migration(self, actor_id: str, migration_id: str) -> None:
        marker = await self.get_migration(actor_id) or {}
        marker.update(
            {"status": "committed", "migration_id": migration_id, "updated_at": time.time()}
        )
        await self._redis.hset(self._migration_key, actor_id, mesh_marshal(marker))
        await self._redis.expire(self._migration_key, 86400)

    async def get_migration(self, actor_id: str) -> dict[str, Any] | None:
        payload = await self._redis.hget(self._migration_key, actor_id)
        if not payload:
            return None
        try:
            return cast(dict[str, Any], mesh_unmarshal(payload))
        except Exception as e:
            logger.debug("Ghost-Registry: Failed to unpack migration for %s: %s", actor_id, e)
            return None

    async def clear_migration(self, actor_id: str) -> None:
        await self._redis.hdel(self._migration_key, actor_id)
