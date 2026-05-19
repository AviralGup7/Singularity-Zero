"""
Cyber Security Test Pipeline - Ghost-Actor Mesh
Implements a location-transparent actor model for elastic scan orchestration.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

import pykka

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
        self.is_migrating = False
        self._last_health_check = 0.0
        self._evacuation_recommended = False

    def on_receive(self, message: dict[str, Any]) -> Any:
        if not isinstance(message, dict) or "command" not in message:
            logger.error("Ghost-Actor [%s] failure: Invalid message format", self.actor_id)
            return {"status": "error", "error": "Invalid message format"}

        command = message.get("command")

        if command == "execute":
            # Auto-check health before execution
            self._check_local_health()
            return self._execute_logic(message.get("input", {}))

        elif command == "snapshot":
            return ActorState(
                actor_id=self.actor_id,
                stage=self.state.get("current_stage", "init"),
                data=self.state,
                checkpoint_ts=time.time(),
                evacuation_recommended=self._evacuation_recommended,
            )

        elif command == "migrate":
            self.is_migrating = True
            snapshot = self.on_receive({"command": "snapshot"})
            logger.warning("Ghost-Actor [%s]: Initiating migration (Evac Recommended: %s)",
                           self.actor_id, self._evacuation_recommended)
            self.stop()
            return snapshot

        elif command == "health_check":
            self._check_local_health()
            return {
                "actor_id": self.actor_id,
                "evacuation_recommended": self._evacuation_recommended,
                "node_cpu": psutil.cpu_percent() if psutil else 0.0,
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
            cpu = psutil.cpu_percent()
            ram_pct = psutil.virtual_memory().percent

            # Proactive evacuation if CPU > 90% or RAM > 95%
            if cpu > 90.0 or ram_pct > 95.0:
                if not self._evacuation_recommended:
                    logger.warning("Ghost-Actor [%s]: Node pressure detected (CPU: %.1f%%, RAM: %.1f%%). "
                                   "Flagging for evacuation.", self.actor_id, cpu, ram_pct)
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


class GhostMeshCoordinator:
    """
    Orchestrates actor placement and migration across the Neural-Mesh.
    Uses the NeuralMeshBalancer to decide on target nodes.
    """

    def __init__(self, registry: GhostMeshRegistry, gossip: Any) -> None:
        self.registry = registry
        self.gossip = gossip
        from src.infrastructure.mesh.balancer import NeuralMeshBalancer
        self.balancer = NeuralMeshBalancer()

    async def migrate_if_needed(self, actor_ref: pykka.ActorRef, task_metadata: dict[str, Any]) -> bool:
        """
        Check if an actor should be migrated and execute the move if a better node is found.
        Returns True if migration was successful.
        """
        try:
            health = actor_ref.ask({"command": "health_check"})
            if not health.get("evacuation_recommended"):
                return False

            actor_id = health["actor_id"]
            logger.info("Ghost-Coordinator: Initiating proactive migration for [%s]", actor_id)

            target_node_id = self.balancer.select_best_node_from_gossip(self.gossip, task_metadata)
            current_node_id = await self.registry.find_actor(actor_id)

            if target_node_id and target_node_id != current_node_id:
                logger.info("Ghost-Coordinator: Migrating [%s] from %s -> %s",
                            actor_id, current_node_id, target_node_id)

                # 1. Snapshot and Stop the actor
                await actor_ref.ask({"command": "migrate"})

                # 2. Update Registry
                await self.registry.register_actor(actor_id, target_node_id)

                # 3. In a real system, we would now signal the remote node to spawn the actor.
                # For this implementation, we assume the registry update is the 'handoff'.
                return True

            return False
        except Exception as e:
            logger.error("Ghost-Coordinator: Migration failed: %s", e)
            return False


class GhostMeshRegistry:
    """
    Global Registry for Location-Transparent Actors.
    Ensures that the orchestrator can find actors regardless of which node they reside on.
    """

    def __init__(self, redis_client: Any, run_id: str = "default") -> None:
        self._redis = redis_client
        self._registry_key = f"cyber:ghost:registry:{run_id}"

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
