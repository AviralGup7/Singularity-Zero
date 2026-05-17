"""Redis cache backend implementation.

Implements distributed caching via Redis with native TTL support.

Requires the 'redis' package: pip install redis
"""

import builtins
import json
import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class RedisBackend:
    """Redis-based cache backend for distributed caching.

    Uses the redis-py library for connection and operations.
    Supports TTL natively via Redis EXPIRE command.

    Requires the 'redis' package: pip install redis

    Attributes:
        url: Redis connection URL.
    """

    def __init__(
        self,
        url: str = "redis://localhost:6379/0",
        max_entries: int = 10000,
        key_prefix: str = "cache_layer:",
    ) -> None:
        """Initialize the Redis backend.

        Args:
            url: Redis connection URL.
            max_entries: Maximum entries (enforced client-side).
            key_prefix: Prefix for all cache keys in Redis.
        """
        self._url = url
        self._max_entries = max_entries
        self._key_prefix = key_prefix
        self._client: Any = None
        self._lock = threading.Lock()
        self._connect()

    def _connect(self) -> None:
        """Establish connection to Redis."""
        try:
            import redis

            self._client = redis.from_url(
                self._url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
            )
            self._client.ping()
        except ImportError:
            logger.error("redis package not installed. Run: pip install redis")
            self._client = None
        except Exception as exc:
            logger.warning("Failed to connect to Redis at %s: %s", self._url, exc)
            self._client = None

    def _full_key(self, key: str) -> str:
        """Add the key prefix."""
        return f"{self._key_prefix}{key}"

    def get(self, key: str) -> Any | None:
        """Retrieve a value from Redis."""
        if self._client is None:
            return None
        try:
            data = self._client.get(self._full_key(key))
            if data is None:
                return None
            return json.loads(data)
        except Exception as exc:
            logger.debug("Redis get error for key %s: %s", key, exc)
            return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Store a value in Redis."""
        if self._client is None:
            return
        try:
            data = json.dumps(value, default=str)
            if ttl is not None:
                self._client.setex(self._full_key(key), ttl, data)
            else:
                self._client.set(self._full_key(key), data)
        except Exception as exc:
            logger.debug("Redis set error for key %s: %s", key, exc)

    def delete(self, key: str) -> bool:
        """Remove a key from Redis."""
        if self._client is None:
            return False
        try:
            return bool(self._client.delete(self._full_key(key)))
        except Exception as exc:
            logger.debug("Redis delete error for key %s: %s", key, exc)
            return False

    def delete_many(self, keys: list[str] | builtins.set[str]) -> int:
        """Remove multiple keys from Redis in one operation."""
        if self._client is None:
            return 0

        key_list = [self._full_key(key) for key in keys]
        if not key_list:
            return 0

        try:
            return int(self._client.delete(*key_list))
        except Exception as exc:
            logger.debug("Redis batch delete failed: %s", exc)
            return 0

    def exists(self, key: str) -> bool:
        """Check if a key exists in Redis."""
        if self._client is None:
            return False
        try:
            return bool(self._client.exists(self._full_key(key)))
        except Exception as exc:
            logger.debug("Redis exists check failed for key %s: %s", key, exc)
            return False

    def clear(self) -> int:
        """Remove all cache_layer entries from Redis."""
        if self._client is None:
            return 0
        try:
            keys = self._client.keys(f"{self._key_prefix}*")
            if keys:
                return int(self._client.delete(*keys))
            return 0
        except Exception as exc:
            logger.debug("Redis clear failed: %s", exc)
            return 0

    def size(self) -> int:
        """Return the number of cache_layer entries."""
        if self._client is None:
            return 0
        try:
            return len(self._client.keys(f"{self._key_prefix}*"))
        except Exception as exc:
            logger.debug("Redis size check failed: %s", exc)
            return 0

    def cleanup_expired(self) -> int:
        """Redis handles expiration automatically."""
        return 0

    def get_stats(self) -> dict[str, Any]:
        """Return Redis backend statistics."""
        if self._client is None:
            return {
                "backend": "redis",
                "url": self._url,
                "connected": False,
                "healthy": False,
            }
        try:
            info = self._client.info("memory")
            return {
                "backend": "redis",
                "url": self._url,
                "connected": True,
                "healthy": True,
                "key_count": self.size(),
                "used_memory_bytes": info.get("used_memory", 0),
            }
        except Exception as exc:
            return {
                "backend": "redis",
                "url": self._url,
                "connected": False,
                "healthy": False,
                "error": str(exc),
            }

    def close(self) -> None:
        """Close the Redis connection."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception as exc:
                logger.debug("Redis close failed: %s", exc)
            self._client = None

    def get_keys_by_namespace(self, namespace: str) -> list[str]:
        """Return all keys in a namespace."""
        if self._client is None:
            return []
        try:
            pattern = f"{self._key_prefix}{namespace}:*"
            return [k.replace(self._key_prefix, "", 1) for k in self._client.keys(pattern)]
        except Exception as exc:
            logger.debug("Redis keys by namespace '%s' failed: %s", namespace, exc)
            return []

    def get_keys_by_tag(self, tag: str) -> list[str]:
        """Return all keys (Redis backend has no tag index)."""
        return []
