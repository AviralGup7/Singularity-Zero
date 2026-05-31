"""Redis cache backend implementation.

Implements distributed caching via Redis with native TTL support.

Requires the 'redis' package: pip install redis
"""

import builtins
import json
import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from src.core.security.circuit_breaker import CircuitBreaker, CircuitBreakerOpenException
from src.infrastructure.cache.backends.memory import MemoryBackend

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
        self._fallback = MemoryBackend(max_entries=max_entries)
        self._breaker = CircuitBreaker("redis-cache", failure_threshold=3, recovery_timeout=15.0)
        self._last_connect_attempt = 0.0
        self._connect_retry_seconds = 15.0
        self._connect()

    def _connect(self) -> None:
        """Establish connection to Redis."""
        self._last_connect_attempt = time.monotonic()
        try:
            import redis

            self._client = redis.from_url(
                self._url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30,
                socket_keepalive=True,
                max_connections=20,
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
            self._maybe_reconnect()
            if self._client is None:
                return self._fallback.get(key)
        try:
            data = self._call(lambda: self._client.get(self._full_key(key)))
            if data is None:
                return self._fallback.get(key)
            value = json.loads(data)
            self._fallback.set(key, value)
            return value
        except Exception as exc:
            logger.warning("Redis get failed for key %s; using local fallback: %s", key, exc)
            return self._fallback.get(key)

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Store a value in Redis."""
        self._fallback.set(key, value, ttl=ttl)
        if self._client is None:
            self._maybe_reconnect()
            if self._client is None:
                return
        try:
            data = json.dumps(value, default=str)
            if ttl is not None:
                self._call(lambda: self._client.setex(self._full_key(key), ttl, data))
            else:
                self._call(lambda: self._client.set(self._full_key(key), data))
        except Exception as exc:
            logger.warning(
                "Redis set failed for key %s; value kept in local fallback: %s", key, exc
            )

    def delete(self, key: str) -> bool:
        """Remove a key from Redis."""
        fallback_deleted = self._fallback.delete(key)
        if self._client is None:
            self._maybe_reconnect()
            if self._client is None:
                return fallback_deleted
        try:
            return (
                bool(self._call(lambda: self._client.delete(self._full_key(key))))
                or fallback_deleted
            )
        except Exception as exc:
            logger.warning(
                "Redis delete failed for key %s; applied local fallback only: %s", key, exc
            )
            return fallback_deleted

    def delete_many(self, keys: list[str] | builtins.set[str]) -> int:
        """Remove multiple keys from Redis in one operation."""
        fallback_removed = self._fallback.delete_many(keys)
        if self._client is None:
            self._maybe_reconnect()
            if self._client is None:
                return fallback_removed

        key_list = [self._full_key(key) for key in keys]
        if not key_list:
            return 0

        try:
            return int(self._call(lambda: self._client.delete(*key_list))) + fallback_removed
        except Exception as exc:
            logger.warning("Redis batch delete failed; applied local fallback only: %s", exc)
            return fallback_removed

    def exists(self, key: str) -> bool:
        """Check if a key exists in Redis."""
        if self._client is None:
            self._maybe_reconnect()
            if self._client is None:
                return self._fallback.exists(key)
        try:
            return bool(
                self._call(lambda: self._client.exists(self._full_key(key)))
            ) or self._fallback.exists(key)
        except Exception as exc:
            logger.warning(
                "Redis exists check failed for key %s; using local fallback: %s", key, exc
            )
            return self._fallback.exists(key)

    def clear(self) -> int:
        """Remove all cache_layer entries from Redis."""
        fallback_removed = self._fallback.clear()
        if self._client is None:
            self._maybe_reconnect()
            if self._client is None:
                return fallback_removed
        try:
            keys = list(self._client.scan_iter(match=f"{self._key_prefix}*", count=500))
            if keys:
                return int(self._call(lambda: self._client.delete(*keys))) + fallback_removed
            return fallback_removed
        except Exception as exc:
            logger.warning("Redis clear failed; local fallback cleared: %s", exc)
            return fallback_removed

    def size(self) -> int:
        """Return the number of cache_layer entries."""
        fallback_size = self._fallback.size()
        if self._client is None:
            self._maybe_reconnect()
            if self._client is None:
                return fallback_size
        try:
            return (
                sum(1 for _ in self._client.scan_iter(match=f"{self._key_prefix}*", count=500))
                + fallback_size
            )
        except Exception as exc:
            logger.warning("Redis size check failed; using local fallback size: %s", exc)
            return fallback_size

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
                "fallback": "memory",
                "fallback_entries": self._fallback.size(),
            }
        try:
            info = self._call(lambda: self._client.info("memory"))
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
                "fallback": "memory",
                "fallback_entries": self._fallback.size(),
            }

    def close(self) -> None:
        """Close the Redis connection."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception as exc:
                logger.debug("Redis close failed: %s", exc)
            self._client = None
        self._fallback.close()

    def get_keys_by_namespace(self, namespace: str) -> list[str]:
        """Return all keys in a namespace."""
        fallback_keys = self._fallback.get_keys_by_namespace(namespace)
        if self._client is None:
            self._maybe_reconnect()
            if self._client is None:
                return fallback_keys
        try:
            pattern = f"{self._key_prefix}{namespace}:*"
            redis_keys = [
                k.replace(self._key_prefix, "", 1)
                for k in self._client.scan_iter(match=pattern, count=500)
            ]
            return sorted(set(redis_keys + fallback_keys))
        except Exception as exc:
            logger.warning(
                "Redis keys by namespace '%s' failed; using local fallback: %s", namespace, exc
            )
            return fallback_keys

    def get_keys_by_tag(self, tag: str) -> list[str]:
        """Return all keys (Redis backend has no tag index)."""
        return []

    def _call(self, fn: Callable[[], Any]) -> Any:
        try:
            return self._breaker.call(fn)
        except CircuitBreakerOpenException:
            raise
        except Exception:
            self._client = None
            raise

    def _maybe_reconnect(self) -> None:
        if time.monotonic() - self._last_connect_attempt < self._connect_retry_seconds:
            return
        with self._lock:
            if self._client is None:
                self._connect()
