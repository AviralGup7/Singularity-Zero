"""
Cyber Security Test Pipeline - Redis-backed FP Repository
Provides centralized storage for learned false-positive patterns.
"""

from __future__ import annotations

import json
import logging
from typing import Any, cast

import redis.asyncio as redis

from src.learning.models.fp_pattern import FPPattern

logger = logging.getLogger(__name__)


class RedisFPRepository:
    """
    Centralized FP Pattern Repository.
    Stores patterns in Redis for mesh-wide access and real-time synchronization.
    """

    def __init__(self, redis_url: str, key_prefix: str = "cyber:fp_patterns"):
        self._client = redis.from_url(redis_url, decode_responses=True)
        self._key = key_prefix

    @property
    def key(self) -> str:
        from src.core.tenant_context import TenantContext

        tenant_id = TenantContext.get_current_tenant()
        if tenant_id:
            return f"{tenant_id}:{self._key}"
        return self._key

    async def upsert_pattern(self, pattern: FPPattern) -> None:
        """Insert or update an FP pattern in Redis."""
        try:
            row = pattern.to_db_row()
            # Convert any non-serializable fields if necessary (already handled by to_db_row usually)
            await cast(Any, self._client).hset(self.key, pattern.pattern_id, json.dumps(row))
        except Exception as e:
            logger.error("RedisFPRepo: Failed to upsert pattern %s: %s", pattern.pattern_id, e)

    async def get_pattern(self, pattern_id: str) -> FPPattern | None:
        """Fetch a specific pattern by ID."""
        try:
            data = await cast(Any, self._client).hget(self.key, pattern_id)
            if data:
                return FPPattern.from_db_row(json.loads(data))
        except Exception as e:
            logger.error("RedisFPRepo: Failed to get pattern %s: %s", pattern_id, e)
        return None

    async def list_patterns(self, active_only: bool = True) -> list[FPPattern]:
        """List all patterns stored in Redis."""
        try:
            all_data = await cast(Any, self._client).hgetall(self.key)
            patterns = []
            for data in all_data.values():
                p = FPPattern.from_db_row(json.loads(data))
                if not active_only or p.is_active:
                    patterns.append(p)
            return patterns
        except Exception as e:
            logger.error("RedisFPRepo: Failed to list patterns: %s", e)
            return []

    async def delete_pattern(self, pattern_id: str) -> None:
        """Remove a pattern from Redis."""
        try:
            await cast(Any, self._client).hdel(self.key, pattern_id)
        except Exception as e:
            logger.error("RedisFPRepo: Failed to delete pattern %s: %s", pattern_id, e)

    async def clear(self) -> None:
        """Clear all patterns from Redis."""
        try:
            await cast(Any, self._client).delete(self.key)
        except Exception as e:
            logger.error("RedisFPRepo: Failed to clear patterns: %s", e)

    async def close(self) -> None:
        """Close the Redis connection."""
        await cast(Any, self._client).close()
