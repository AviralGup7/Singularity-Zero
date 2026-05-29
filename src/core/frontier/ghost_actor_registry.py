"""Global Location-Transparent Actor Registry for Ghost Mesh."""

from __future__ import annotations

import time
from typing import Any, cast

from src.core.frontier.marshaller import mesh_marshal, mesh_unmarshal
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class GhostMeshRegistry:
    """Global Registry for Location-Transparent Actors.

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
        # Increased TTL to 24 hours to prevent mid-scan expirations
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
