"""Cyber Security Test Pipeline - Ghost-Actor Mesh

Implements a location-transparent actor model for elastic scan orchestration.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Any, cast

import pykka

from src.core.frontier.ghost_actor_coordinator import GhostMeshCoordinator as BaseMeshCoordinator

# Modular imports
from src.core.frontier.ghost_actor_state import ActorState
from src.core.frontier.marshaller import (
    mesh_marshal_pickle,
    mesh_unmarshal_pickle,
)
from src.core.frontier.state import CRDTCompactionBudget, stable_digest
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

try:
    import psutil
except ImportError:
    psutil = None

_LOGIC_REGISTRY: dict[str, Callable[[dict[str, Any], dict[str, Any]], Any]] = {}


class ScanActor(pykka.ThreadingActor):
    """Frontier Task Actor.

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

        # Explicit command whitelist — unknown commands are rejected, not silently accepted
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
                # Use a copy of the state to avoid stale references
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
            # Ensure we capture a stable snapshot before stopping
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


class GhostMeshCoordinator(BaseMeshCoordinator):
    """Subclass of GhostMeshCoordinator extending to auto-bind ScanActor."""

    async def spawn_or_rehydrate_actor(
        self, actor_id: str, logic_fn: Callable[[dict[str, Any], dict[str, Any]], Any]
    ) -> pykka.ActorRef:
        """Spawn a new actor, automatically re-hydrating from registry if state exists."""
        return await super().spawn_or_rehydrate_actor(actor_id, logic_fn, ScanActor)
