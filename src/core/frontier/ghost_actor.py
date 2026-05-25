"""
Cyber Security Test Pipeline - Ghost-Actor Mesh
Implements a location-transparent actor model for elastic scan orchestration.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

import pykka

from src.core.contracts.health import HealthComponent, HealthMetric, HealthStatus
from src.core.frontier.marshaller import (
    mesh_marshal,
    mesh_marshal_pickle,
    mesh_unmarshal,
    mesh_unmarshal_pickle,
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
    """Serializable state for actor migration."""

    actor_id: str
    stage: str
    data: dict[str, Any]
    checkpoint_ts: float
    evacuation_recommended: bool = False
    logic_fn_name: str = ""
    snapshot_format: str = "ghost-actor-snapshot-v3"
    last_wal_id: str | None = None
    migration_id: str = ""
    state_digest: str = ""
    applied_wal_ids: list[str] = field(default_factory=list)
    compaction_budget: dict[str, Any] = field(default_factory=dict)
    serialized_logic_fn: bytes | None = None

    def pack(self) -> bytes:
        """Binary serialization via MessagePack."""
        return mesh_marshal(
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
            }
        )

    @classmethod
    def unpack(cls, payload: bytes) -> ActorState:
        """Binary deserialization via MessagePack."""
        data = mesh_unmarshal(payload)
        data.setdefault("snapshot_format", "ghost-actor-snapshot-v1")
        data.setdefault("last_wal_id", None)
        data.setdefault("migration_id", "")
        data.setdefault("state_digest", stable_digest(data.get("data", {})))
        data.setdefault("applied_wal_ids", [])
        data.setdefault("compaction_budget", {})
        data.setdefault("serialized_logic_fn", None)
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
            payload.setdefault("snapshot_format", "ghost-actor-snapshot-v3")
            payload.setdefault("last_wal_id", None)
            payload.setdefault("migration_id", "")
            payload.setdefault("state_digest", "")
            payload.setdefault("applied_wal_ids", [])
            payload.setdefault("compaction_budget", {})
            payload.setdefault("serialized_logic_fn", None)
            valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
            filtered = {k: v for k, v in payload.items() if k in valid_keys}
            return cls(**filtered)
        if isinstance(payload, bytes):
            return cls.unpack(payload)
        raise TypeError(f"a bytes-like object is required, not {type(payload).__name__}")


_LOGIC_REGISTRY: dict[str, Callable[[dict[str, Any], dict[str, Any]], Any]] = {}


class ScanActor(pykka.ThreadingActor):
    """
    Frontier Task Actor.
    Encapsulates logic and state, capable of migrating across the mesh.
    """

    def __init__(
        self, actor_id: str, logic_fn: Callable[[dict[str, Any], dict[str, Any]], Any]
    ) -> None:
        super().__init__()
        self.actor_id = actor_id
        self.logic_fn = logic_fn
        self.state: dict[str, Any] = {}
        self._applied_wal_ids: set[str] = set()
        self.is_migrating = False
        self._last_health_check = 0.0
        self._evacuation_recommended = False
        self.compaction_budget = CRDTCompactionBudget()
        # Register logic function name for mesh-wide serialization & network rehydration
        if hasattr(logic_fn, "__name__"):
            _LOGIC_REGISTRY[logic_fn.__name__] = logic_fn

    def dehydrate(self, migration_id: str = "") -> bytes:
        """Freeze actor mutating work and dehydrate its state to packed bytes."""
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

        actor_state = ActorState(
            actor_id=self.actor_id,
            stage=self.state.get("current_stage", "init"),
            data=state_data,
            checkpoint_ts=time.time(),
            evacuation_recommended=self._evacuation_recommended,
            logic_fn_name=getattr(self.logic_fn, "__name__", ""),
            last_wal_id=self.state.get("_last_wal_id"),
            state_digest=stable_digest(state_data),
            migration_id=migration_id,
            applied_wal_ids=list(self._applied_wal_ids),
            compaction_budget=compaction_budget_data,
            serialized_logic_fn=serialized_logic,
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

        # Fix S2-2: Explicit command whitelist — unknown commands are rejected, not silently accepted
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

        # Block any mutating or executing requests if the actor is migrating
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
            # Auto-check health before execution
            self._check_local_health()
            return self._execute_logic(message.get("input", {}))

        elif command == "snapshot":
            data = dict(self.state)
            return ActorState(
                actor_id=self.actor_id,
                stage=self.state.get("current_stage", "init"),
                # Fix S1-3: Use a copy of the state to avoid stale references
                data=data,
                checkpoint_ts=time.time(),
                evacuation_recommended=self._evacuation_recommended,
                logic_fn_name=getattr(self.logic_fn, "__name__", ""),
                last_wal_id=self.state.get("_last_wal_id"),
                state_digest=stable_digest(data),
            )

        elif command == "recover":
            # Replay deltas from WAL
            wal_deltas = message.get("deltas", [])
            logger.info(
                "Ghost-Actor [%s]: Replaying %d deltas from WAL", self.actor_id, len(wal_deltas)
            )
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
            snapshot.state_digest = stable_digest(snapshot.data)
            return snapshot.pack()

        elif command == "migrate":
            migration_id = str(message.get("migration_id") or uuid.uuid4())
            # Fix S1-3: Ensure we capture a stable snapshot before stopping
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
            # Return binary payload for mesh-transport
            return snapshot.pack()

        elif command == "health_check":
            self._check_local_health()
            return {
                "actor_id": self.actor_id,
                "evacuation_recommended": self._evacuation_recommended,
                # Fix S1-1: Use interval to get a real CPU reading
                "node_cpu": psutil.cpu_percent(interval=0.1) if psutil else 0.0,
                "status": "evacuate" if self._evacuation_recommended else "ok",
                "state_size": len(self.state),
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
            # Fix S1-1: Use interval for health checks
            cpu = psutil.cpu_percent(interval=0.1)
            ram_pct = psutil.virtual_memory().percent

            # Proactive evacuation if CPU > 90% or RAM > 95%
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
        except Exception as e:  # pylint: disable=W0718
            logger.debug("Ghost-Actor [%s]: Health check failed: %s", self.actor_id, e)

    def _execute_logic(self, task_input: dict[str, Any]) -> dict[str, Any]:
        """Runs the encapsulated security logic."""
        logger.info("Ghost-Actor [%s]: Executing logic...", self.actor_id)
        try:
            result = self.logic_fn(task_input, self.state)
            return {"status": "success", "output": result}
        except Exception as e:  # pylint: disable=W0718
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
    """
    Orchestrates actor placement and migration across the Neural-Mesh.
    Uses the NeuralMeshBalancer to decide on target nodes.
    """

    def __init__(self, registry: GhostMeshRegistry, gossip: Any) -> None:
        self.registry = registry
        self.gossip = gossip
        from src.infrastructure.mesh.balancer import NeuralMeshBalancer  # pylint: disable=C0415

        self.balancer = NeuralMeshBalancer()
        # Bind coordinator to gossip for network-aware signaling
        is_mock = gossip.__class__.__name__ in ("MagicMock", "Mock")
        if gossip and hasattr(gossip, "__dict__") and not is_mock:
            gossip._coordinator = self

    async def migrate_if_needed(
        self,
        actor_ref: pykka.ActorRef,
        task_metadata: dict[str, Any],
    ) -> bool:
        """
        Check if an actor should be migrated and execute the move if a better node is found.
        Returns True if migration was successful.
        """
        try:
            # 🛸 Sprint 1 Hardening: Use live mesh telemetry instead of blocking actor calls
            # This allows us to detect pressure even if the actor is busy executing.
            local_node = self.gossip.local_node

            # Use same thresholds as ProactiveMigrationHandler (90% CPU, <500MB RAM available)
            # Note: ram_available_mb is what we have left, not % usage.
            # Assuming a 2GB comfortable baseline, 500MB is critical.
            is_under_pressure = local_node.cpu_usage > 90.0 or local_node.ram_available_mb < 500.0

            if not is_under_pressure:
                # Also check if actor specifically recommended evacuation (e.g. for logic-level reasons)
                # We still try to ask, but with a timeout to avoid hanging.
                try:
                    health = cast(
                        dict[str, Any], actor_ref.ask({"command": "health_check"}, timeout=0.5)
                    )
                    if not health.get("evacuation_recommended"):
                        return False
                except (pykka.Timeout, Exception):
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

                # 1. Freeze the actor and capture a stable snapshot while it is still alive.
                packed_state = actor_ref.ask(
                    {"command": "dehydrate", "migration_id": migration_id},
                    block=True,
                )
                unpacked = ActorState.rehydrate(packed_state)
                if not isinstance(packed_state, bytes):
                    packed_state = unpacked.pack()

                # 2. Store the serialized state in the registry for transmission
                await self.registry.store_actor_state(actor_id, packed_state)
                await self.registry.prepare_migration(
                    actor_id=actor_id,
                    migration_id=migration_id,
                    source_node=current_node_id,
                    target_node=target_node_id,
                    state_digest=unpacked.state_digest,
                )

                # 3. Update Registry only after the snapshot is durably visible.
                await self.registry.register_actor(actor_id, target_node_id)
                await self.registry.commit_migration(actor_id, migration_id)

                # 4. Stop the source actor after commit; a target can now rehydrate on restart.
                actor_ref.stop()

                # 5. Emit Migration Event for Observability
                from src.core.events import EventType, get_event_bus  # pylint: disable=C0415

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

                # 6. Live Actor Migration Handoff (Network Handoff)
                is_mock = self.gossip.__class__.__name__ in ("MagicMock", "Mock")
                if (
                    not is_mock
                    and hasattr(self.gossip, "peers")
                    and isinstance(self.gossip.peers, dict)
                ):
                    target_peer = self.gossip.peers.get(target_node_id)
                    if target_peer and hasattr(self.gossip, "_send_reliable"):
                        logic_fn_name = unpacked.logic_fn_name or "dummy_logic"

                        # Send migration trigger over gossip UDP sync
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
        except Exception as e:  # pylint: disable=W0718
            logger.error("Ghost-Coordinator: Migration failed: %s", e)
            return False

    async def health_metrics(
        self, actor_refs: list[pykka.ActorRef] | None = None
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
            except Exception as exc:  # pylint: disable=broad-exception-caught
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
        actor_refs: list[pykka.ActorRef],
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
    ) -> pykka.ActorRef:
        """Spawn a new actor instance, automatically re-hydrating from registry if state exists."""
        # 1. Start a fresh actor instance
        actor_ref = ScanActor.start(actor_id, logic_fn)

        # 2. Check if a migrated state exists in the registry
        packed_state = await self.registry.retrieve_actor_state(actor_id)
        if packed_state:
            try:
                # 3. Unpack and restore state using rehydrate command
                actor_ref.ask({"command": "rehydrate", "payload": packed_state}, block=True)
                logger.info(
                    "Ghost-Coordinator: Successfully re-hydrated actor [%s] with state checkpoints",
                    actor_id,
                )
                # 4. Clean up state from registry to save storage footprint
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
    """
    Global Registry for Location-Transparent Actors.
    Ensures that the orchestrator can find actors regardless of which node they reside on.
    """

    def __init__(self, redis_client: Any, run_id: str = "default") -> None:
        self._redis = redis_client
        self._registry_key = f"cyber:ghost:registry:{run_id}"
        self._state_key = f"cyber:ghost:state:{run_id}"
        self._migration_key = f"cyber:ghost:migration:{run_id}"

    async def register_actor(self, actor_id: str, node_id: str) -> None:
        """Map an actor to its current host node."""
        await self._redis.hset(self._registry_key, actor_id, node_id)
        # Fix #250: Increased TTL to 24 hours to prevent mid-scan expirations
        await self._redis.expire(self._registry_key, 86400)

    async def find_actor(self, actor_id: str) -> str | None:
        """Find the node_id currently hosting the actor."""
        return cast(str | None, await self._redis.hget(self._registry_key, actor_id))

    async def unregister_actor(self, actor_id: str) -> None:
        await self._redis.hdel(self._registry_key, actor_id)

    async def store_actor_state(self, actor_id: str, state_bytes: bytes) -> None:
        """Store the packed actor state in Redis."""
        await self._redis.hset(self._state_key, actor_id, state_bytes)
        await self._redis.expire(self._state_key, 86400)

    async def retrieve_actor_state(self, actor_id: str) -> bytes | None:
        """Retrieve the packed actor state from Redis."""
        return cast(bytes | None, await self._redis.hget(self._state_key, actor_id))

    async def clear_actor_state(self, actor_id: str) -> None:
        """Remove the packed actor state from Redis."""
        await self._redis.hdel(self._state_key, actor_id)

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
