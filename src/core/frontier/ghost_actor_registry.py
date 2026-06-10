"""Global Location-Transparent Actor Registry for Ghost Mesh."""

from __future__ import annotations

import asyncio
import time
from typing import Any, cast

from src.core.frontier.marshaller import mesh_marshal, mesh_unmarshal
from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.queue.redis_config import (
    REDIS_BACKOFF_SECONDS,
    REDIS_TIMEOUT_SECONDS,
)
from src.infrastructure.queue.redis_config import (
    REDIS_MAX_RETRIES as REDIS_RETRIES,
)
from src.infrastructure.queue.redis_config import (
    REDIS_RECONNECT_SECONDS as DEGRADED_RETRY_SECONDS,
)

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
        self._degraded_until = 0.0
        self._fallback_registry: dict[str, str] = {}
        self._fallback_state: dict[str, bytes] = {}
        self._fallback_migrations: dict[str, bytes] = {}

    async def register_actor(self, actor_id: str, node_id: str) -> bool:
        """Map an actor to its current host node."""
        self._fallback_registry[actor_id] = node_id
        try:
            await self._call("hset", self._registry_key, actor_id, node_id)
            await self._call("expire", self._registry_key, 86400)
            return True
        except Exception as exc:
            logger.warning("Ghost-Registry degraded: actor registration kept locally: %s", exc)
            return False

    async def find_actor(self, actor_id: str) -> str | None:
        """Find the node_id currently hosting the actor."""
        try:
            value = await self._call("hget", self._registry_key, actor_id)
            if value is not None:
                node_id = value.decode() if isinstance(value, bytes) else str(value)
                self._fallback_registry[actor_id] = node_id
                return node_id
        except Exception as exc:
            logger.warning("Ghost-Registry degraded: actor lookup served locally: %s", exc)
        return self._fallback_registry.get(actor_id)

    async def unregister_actor(self, actor_id: str) -> None:
        self._fallback_registry.pop(actor_id, None)
        try:
            await self._call("hdel", self._registry_key, actor_id)
        except Exception as exc:
            logger.warning("Ghost-Registry degraded: unregister applied locally: %s", exc)

    async def store_actor_state(self, actor_id: str, state_bytes: bytes) -> bool:
        """Store the packed actor state in Redis."""
        self._fallback_state[actor_id] = state_bytes
        try:
            await self._call("hset", self._state_key, actor_id, state_bytes)
            await self._call("expire", self._state_key, 86400)
            return True
        except Exception as exc:
            logger.warning("Ghost-Registry degraded: actor state kept locally: %s", exc)
            return False

    async def retrieve_actor_state(self, actor_id: str) -> bytes | None:
        """Retrieve the packed actor state from Redis."""
        try:
            value = await self._call("hget", self._state_key, actor_id)
            if value is not None:
                state = value if isinstance(value, bytes) else str(value).encode()
                self._fallback_state[actor_id] = state
                return state
        except Exception as exc:
            logger.warning("Ghost-Registry degraded: actor state served locally: %s", exc)
        return self._fallback_state.get(actor_id)

    async def clear_actor_state(self, actor_id: str) -> None:
        """Remove the packed actor state from Redis."""
        self._fallback_state.pop(actor_id, None)
        try:
            await self._call("hdel", self._state_key, actor_id)
        except Exception as exc:
            logger.warning("Ghost-Registry degraded: clear actor state applied locally: %s", exc)

    async def prepare_migration(
        self,
        *,
        actor_id: str,
        migration_id: str,
        source_node: str,
        target_node: str,
        state_digest: str,
    ) -> bool:
        """Record an in-flight migration before changing actor ownership."""
        payload = mesh_marshal(
            {
                "status": "prepared",
                "actor_id": actor_id,
                "migration_id": migration_id,
                "source_node": source_node,
                "target_node": target_node,
                "state_digest": state_digest,
                "updated_at": time.time(),
            }
        )
        self._fallback_migrations[actor_id] = payload
        try:
            await self._call("hset", self._migration_key, actor_id, payload)
            await self._call("expire", self._migration_key, 86400)
            return True
        except Exception as exc:
            logger.warning("Ghost-Registry degraded: migration prepare kept locally: %s", exc)
            return False

    async def commit_migration(self, actor_id: str, migration_id: str) -> bool:
        marker = await self.get_migration(actor_id) or {}
        marker.update(
            {"status": "committed", "migration_id": migration_id, "updated_at": time.time()}
        )
        payload = mesh_marshal(marker)
        self._fallback_migrations[actor_id] = payload
        try:
            await self._call("hset", self._migration_key, actor_id, payload)
            await self._call("expire", self._migration_key, 86400)
            return True
        except Exception as exc:
            logger.warning("Ghost-Registry degraded: migration commit kept locally: %s", exc)
            return False

    async def get_migration(self, actor_id: str) -> dict[str, Any] | None:
        try:
            payload = await self._call("hget", self._migration_key, actor_id)
            if payload:
                self._fallback_migrations[actor_id] = (
                    payload if isinstance(payload, bytes) else str(payload).encode()
                )
        except Exception as exc:
            logger.warning("Ghost-Registry degraded: migration lookup served locally: %s", exc)
            payload = self._fallback_migrations.get(actor_id)
        if not payload:
            return None
        try:
            return cast(dict[str, Any], mesh_unmarshal(payload))
        except Exception as e:
            logger.debug("Ghost-Registry: Failed to unpack migration for %s: %s", actor_id, e)
            return None

    async def clear_migration(self, actor_id: str) -> None:
        self._fallback_migrations.pop(actor_id, None)
        try:
            await self._call("hdel", self._migration_key, actor_id)
        except Exception as exc:
            logger.warning("Ghost-Registry degraded: clear migration applied locally: %s", exc)

    # Allowed Redis methods for the registry
    _ALLOWED_REDIS_METHODS = frozenset(
        {
            "hset",
            "hget",
            "hdel",
            "expire",
            "get",
            "set",
            "delete",
        }
    )

    async def _call(self, method: str, *args: Any) -> Any:
        if self._redis is None:
            raise ConnectionError("No Redis client configured for Ghost registry")
        if method not in self._ALLOWED_REDIS_METHODS:
            raise ValueError(f"Disallowed Redis method: {method!r}")
        now = time.monotonic()
        if now < self._degraded_until:
            raise TimeoutError("Ghost registry Redis circuit is open")
        delay = REDIS_BACKOFF_SECONDS
        last_error: Exception | None = None
        for attempt in range(REDIS_RETRIES + 1):
            try:
                call = getattr(self._redis, method)
                return await asyncio.wait_for(call(*args), timeout=REDIS_TIMEOUT_SECONDS)
            except Exception as exc:
                last_error = exc
                if attempt >= REDIS_RETRIES:
                    break
                await asyncio.sleep(delay)
                delay *= 2
        self._degraded_until = time.monotonic() + DEGRADED_RETRY_SECONDS
        raise last_error or RuntimeError("Ghost registry Redis operation failed")
