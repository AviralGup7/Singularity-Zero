"""
Cyber Security Test Pipeline - Redis-backed FP Repository
Provides centralized storage for learned false-positive patterns.
"""

from __future__ import annotations

import json
import logging
import time
import asyncio
from typing import Any, cast

import redis.asyncio as redis

from src.learning.models.fp_pattern import FPPattern

logger = logging.getLogger(__name__)

DEFAULT_REDIS_TIMEOUT_SECONDS = 3.0
DEFAULT_REDIS_RETRIES = 2
DEFAULT_REDIS_BACKOFF_SECONDS = 0.1
DEFAULT_DEGRADED_RETRY_SECONDS = 30.0


class RedisFPRepository:
    """
    Centralized FP Pattern Repository.
    Stores patterns in Redis for mesh-wide access and real-time synchronization.
    """

    def __init__(self, redis_url: str, key_prefix: str = "cyber:fp_patterns"):
        self._client = redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=DEFAULT_REDIS_TIMEOUT_SECONDS,
            socket_timeout=DEFAULT_REDIS_TIMEOUT_SECONDS,
            health_check_interval=30,
            max_connections=10,
            retry_on_timeout=True,
        )
        self._key = key_prefix
        self._fallback: dict[str, str] = {}
        self._degraded_until = 0.0
        self._closed = False

    @property
    def key(self) -> str:
        from src.core.tenant_context import TenantContext

        tenant_id = TenantContext.get_current_tenant()
        if tenant_id:
            return f"{tenant_id}:{self._key}"
        return self._key

    async def upsert_pattern(self, pattern: FPPattern) -> None:
        """Insert or update an FP pattern in Redis."""
        row = pattern.to_db_row()
        serialized = json.dumps(row)
        self._fallback[pattern.pattern_id] = serialized
        try:
            await self._redis_call("hset", self.key, pattern.pattern_id, serialized)
        except Exception as e:
            logger.warning(
                "RedisFPRepo degraded: stored pattern %s in local fallback after Redis failure: %s",
                pattern.pattern_id,
                e,
            )

    async def get_pattern(self, pattern_id: str) -> FPPattern | None:
        """Fetch a specific pattern by ID."""
        try:
            data = await self._redis_call("hget", self.key, pattern_id)
            if data:
                return FPPattern.from_db_row(json.loads(data))
        except Exception as e:
            logger.warning("RedisFPRepo degraded: reading pattern %s from local fallback: %s", pattern_id, e)
        data = self._fallback.get(pattern_id)
        if data:
            return FPPattern.from_db_row(json.loads(data))
        return None

    async def list_patterns(self, active_only: bool = True) -> list[FPPattern]:
        """List all patterns stored in Redis."""
        try:
            all_data = await self._redis_call("hgetall", self.key)
            if all_data:
                self._fallback.update({str(k): str(v) for k, v in all_data.items()})
                return self._deserialize_patterns(all_data.values(), active_only=active_only)
        except Exception as e:
            logger.warning("RedisFPRepo degraded: listing patterns from local fallback: %s", e)
        return self._deserialize_patterns(self._fallback.values(), active_only=active_only)

    async def delete_pattern(self, pattern_id: str) -> None:
        """Remove a pattern from Redis."""
        self._fallback.pop(pattern_id, None)
        try:
            await self._redis_call("hdel", self.key, pattern_id)
        except Exception as e:
            logger.warning("RedisFPRepo degraded: delete pattern %s applied only locally: %s", pattern_id, e)

    async def clear(self) -> None:
        """Clear all patterns from Redis."""
        self._fallback.clear()
        try:
            await self._redis_call("delete", self.key)
        except Exception as e:
            logger.warning("RedisFPRepo degraded: clear applied only locally: %s", e)

    async def close(self) -> None:
        """Close the Redis connection."""
        self._closed = True
        try:
            await cast(Any, self._client).aclose()
        except AttributeError:
            await cast(Any, self._client).close()
        except Exception as e:
            logger.debug("RedisFPRepo: Redis close failed: %s", e)

    async def _redis_call(self, method: str, *args: Any) -> Any:
        if self._closed:
            raise RuntimeError("RedisFPRepository is closed")
        now = time.monotonic()
        if now < self._degraded_until:
            raise TimeoutError("RedisFPRepository circuit is open")
        delay = DEFAULT_REDIS_BACKOFF_SECONDS
        last_error: Exception | None = None
        for attempt in range(DEFAULT_REDIS_RETRIES + 1):
            try:
                call = getattr(cast(Any, self._client), method)
                return await asyncio.wait_for(call(*args), timeout=DEFAULT_REDIS_TIMEOUT_SECONDS)
            except Exception as exc:
                last_error = exc
                if attempt >= DEFAULT_REDIS_RETRIES:
                    break
                await asyncio.sleep(delay)
                delay *= 2
        self._degraded_until = time.monotonic() + DEFAULT_DEGRADED_RETRY_SECONDS
        raise last_error or RuntimeError("Redis operation failed")

    def _deserialize_patterns(self, rows: Any, *, active_only: bool) -> list[FPPattern]:
        patterns: list[FPPattern] = []
        for data in rows:
            try:
                p = FPPattern.from_db_row(json.loads(data))
            except Exception as exc:
                logger.warning("RedisFPRepo: skipping malformed FP pattern payload: %s", exc)
                continue
            if not active_only or p.is_active:
                patterns.append(p)
        return patterns
