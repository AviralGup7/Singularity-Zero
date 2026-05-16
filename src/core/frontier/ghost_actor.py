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

@dataclass
class ActorState:
    """Serializable state for actor migration."""
    actor_id: str
    stage: str
    data: dict[str, Any]
    checkpoint_ts: float

class ScanActor(pykka.ThreadingActor):
    """
    Frontier Task Actor.
    Encapsulates logic and state, capable of migrating across the mesh.
    """
    def __init__(self, actor_id: str, logic_fn: Callable[[dict[str, Any], dict[str, Any]], Any]) -> None:
        super().__init__()
        self.actor_id = actor_id
        self.logic_fn = logic_fn
        self.state: dict[str, Any] = {}
        self.is_migrating = False

    def on_receive(self, message: dict[str, Any]) -> Any:
        if not isinstance(message, dict) or "command" not in message:
            logger.error("Ghost-Actor [%s] failure: Invalid message format", self.actor_id)
            return {"status": "error", "error": "Invalid message format"}

        command = message.get("command")

        if command == "execute":
            return self._execute_logic(message.get("input", {}))

        elif command == "snapshot":
            return ActorState(
                actor_id=self.actor_id,
                stage=self.state.get("current_stage", "init"),
                data=self.state,
                checkpoint_ts=time.time()
            )

        elif command == "migrate":
            self.is_migrating = True
            snapshot = self.on_receive({"command": "snapshot"})
            self.stop()
            return snapshot

        else:
            logger.error("Ghost-Actor [%s] failure: Unknown command %s", self.actor_id, command)
            return {"status": "error", "error": f"Unknown command: {command}"}

    def _execute_logic(self, task_input: dict[str, Any]) -> dict[str, Any]:
        """Runs the encapsulated security logic."""
        logger.info("Ghost-Actor [%s]: Executing logic...", self.actor_id)
        try:
            result = self.logic_fn(task_input, self.state)
            return {"status": "success", "output": result}
        except Exception as e:
            logger.error("Ghost-Actor [%s] failure: %s", self.actor_id, e)
            return {"status": "error", "error": str(e)}

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
