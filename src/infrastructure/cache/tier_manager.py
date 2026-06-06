"""Multi-tier cache coordination.

TierManager owns the lifecycle and read/write paths across L1 (memory), L2
(SQLite/Redis), and L3 (file) cache tiers.  CacheManager delegates all
tier-level operations here so that the orchestrator can focus on invalidation
strategies, warming, metrics, and distributed locking.
"""

from __future__ import annotations

import builtins
import hashlib
import logging
import time
from typing import TYPE_CHECKING, Any, cast

from src.infrastructure.cache.backends import (
    FileBackend,
    MemoryBackend,
    RedisBackend,
    SQLiteBackend,
)
from src.infrastructure.cache.models import CacheMetrics, CacheStats
from src.infrastructure.cache.telemetry import build_cache_efficiency_snapshot

if TYPE_CHECKING:
    from src.core.frontier.bloom import NeuralBloomFilter
    from src.core.frontier.bloom_mesh import BloomMeshSynchronizer, NeuralBloomMesh

logger = logging.getLogger(__name__)


class TierManager:
    """Coordinates L1/L2/L3 cache tiers for a single CacheManager instance.

    TierManager is responsible for:
    - Backend initialization based on cache configuration.
    - Read path (L1 → L2 → L3 cascade with backfill).
    - Write path (write-through to all enabled tiers).
    - Delete / exists / clear operations across tiers.
    - Statistics aggregation and telemetry snapshots.
    - Distributed lock helpers on the L2 Redis backend.

    TierManager does NOT own:
    - Invalidation strategies (managed by CacheManager via InvalidationEngine).
    - Cache warming (managed by CacheManager via warming helpers).
    """

    def __init__(self, config: Any) -> None:
        """Initialize the tier manager without yet creating backends.

        Args:
            config: CacheConfig instance controlling backend creation.
        """
        self._config = config
        self._metrics = CacheMetrics()
        self._l1: MemoryBackend | None = None
        self._l2: SQLiteBackend | RedisBackend | None = None
        self._l3: FileBackend | None = None
        self._bloom_synchronizer: NeuralBloomMesh | BloomMeshSynchronizer | None = None
        self._bloom_filter: NeuralBloomFilter | None = None
        self._lock_redis_client: Any = None
        self._initialized = False
        self.init_backends()
        self._initialized = True

    def init_backends(self) -> None:
        """Initialize enabled cache backends from the current config."""
        if self._config.enable_l1:
            self._l1 = MemoryBackend(max_entries=self._config.max_entries)
            logger.debug("L1 (memory) backend initialized")

        if self._config.enable_l2:
            if self._config.l2_backend == "redis":
                self._l2 = RedisBackend(url=self._config.redis_url or "redis://localhost:6379/0")
                logger.debug("L2 (redis) backend initialized")
            else:
                self._l2 = SQLiteBackend(
                    db_path=self._config.sqlite_db_path,
                    max_entries=self._config.max_entries,
                )
                logger.debug("L2 (sqlite) backend initialized")

        if self._config.enable_l3:
            self._l3 = FileBackend(
                cache_dir=self._config.cache_dir,
                max_entries=self._config.max_entries,
                enable_compression=self._config.enable_compression,
            )
            logger.debug("L3 (file) backend initialized")

    def set_bloom_synchronizer(self, synchronizer: Any) -> None:
        """Register the active Bloom mesh synchronizer."""
        self._bloom_synchronizer = synchronizer

    def is_redundant_query(self, key: str, namespace: str = "default") -> bool:
        """Check the Bloom routing path to reject redundant queries."""
        bf = self.bloom_filter
        if bf is not None:
            full_key = self._make_key(key, namespace)
            return full_key not in bf
        return False

    def set_bloom_filter(self, bloom_filter: NeuralBloomFilter) -> None:
        """Register a direct Bloom filter."""
        self._bloom_filter = bloom_filter

    @property
    def bloom_filter(self) -> NeuralBloomFilter | None:
        """Resolve the active Bloom filter."""
        if self._bloom_synchronizer is not None:
            return self._bloom_synchronizer.filter
        return self._bloom_filter

    def get(self, key: str, namespace: str = "default", default: Any | None = None) -> Any | None:
        """Retrieve a value from the cache hierarchy.

        Checks L1 first, then L2, then L3. On a hit in a lower tier,
        the value is backfilled to higher tiers.
        """
        if not self._config.enabled:
            return default
        if not self._config.is_namespace_enabled(namespace):
            return default

        full_key = self._make_key(key, namespace)
        start = time.monotonic()

        try:
            if self._l1 is not None:
                value = self._l1.get(full_key)
                if value is not None:
                    elapsed = (time.monotonic() - start) * 1000
                    self._metrics.record_hit(elapsed)
                    if self._config.log_cache_ops:
                        logger.debug("L1 HIT: %s", full_key)
                    return value

            if self._l2 is not None:
                value = self._l2.get(full_key)
                if value is not None:
                    elapsed = (time.monotonic() - start) * 1000
                    self._metrics.record_hit(elapsed)
                    ttl = self._get_ttl_remaining(self._l2, full_key)
                    if self._l1 is not None:
                        self._backfill(self._l1, self._l2, full_key, value, ttl, namespace)
                    if self._config.log_cache_ops:
                        logger.debug("L2 HIT (backfilled to L1): %s", full_key)
                    return value

            if self._l3 is not None:
                value = self._l3.get(full_key)
                if value is not None:
                    elapsed = (time.monotonic() - start) * 1000
                    self._metrics.record_hit(elapsed)
                    ttl = self._get_ttl_remaining(self._l3, full_key)
                    if self._l1 is not None:
                        self._backfill(self._l1, self._l3, full_key, value, ttl, namespace)
                    if self._l2 is not None:
                        self._backfill(self._l2, self._l3, full_key, value, ttl, namespace)
                    if self._config.log_cache_ops:
                        logger.debug("L3 HIT (backfilled to higher tiers): %s", full_key)
                    return value

            elapsed = (time.monotonic() - start) * 1000
            self._metrics.record_miss(elapsed)
            if self._config.log_cache_ops:
                logger.debug("MISS: %s", full_key)
            return default
        except Exception as exc:
            logger.warning("Cache get error for %s: %s", full_key, exc)
            self._metrics.record_error()
            return default

    def set(
        self,
        key: str,
        value: Any,
        ttl: int | None = None,
        namespace: str = "default",
        tags: builtins.set[str] | None = None,
        depends_on: builtins.set[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Store a value in all enabled cache tiers (write-through)."""
        if not self._config.enabled:
            return
        if not self._config.is_namespace_enabled(namespace):
            return

        if ttl is None:
            ns_config = self._config.get_namespace_ttl(namespace)
            ttl = (
                ns_config.ttl_seconds
                if hasattr(ns_config, "ttl_seconds")
                else self._config.default_ttl
            )

        full_key = self._make_key(key, namespace)
        start = time.monotonic()
        try:
            bf = self.bloom_filter
            if bf is not None:
                bf.add(full_key)

            self._write_to_tiers(full_key, value, ttl, namespace, tags, depends_on, metadata)
            elapsed = (time.monotonic() - start) * 1000
            self._metrics.record_set(elapsed)
            if self._config.log_cache_ops:
                logger.debug("SET: %s (ttl=%ds, tags=%s)", full_key, ttl, tags)
        except Exception as exc:
            logger.warning("Cache set error for %s: %s", full_key, exc)
            self._metrics.record_error()

    def delete(self, key: str, namespace: str = "default") -> bool:
        """Delete a key from all cache tiers and return whether it was deleted."""
        full_key = self._make_key(key, namespace)
        deleted = False
        try:
            if self._l1 is not None:
                if self._l1.delete(full_key):
                    deleted = True
            if self._l2 is not None:
                if self._l2.delete(full_key):
                    deleted = True
            if self._l3 is not None:
                if self._l3.delete(full_key):
                    deleted = True
            self._metrics.record_delete()
            return deleted
        except Exception as exc:
            logger.warning("Cache delete error for %s: %s", full_key, exc)
            self._metrics.record_error()
            return deleted

    def exists(self, key: str, namespace: str = "default") -> bool:
        """Check if a key exists in any cache tier."""
        full_key = self._make_key(key, namespace)
        try:
            if self._l1 is not None and self._l1.exists(full_key):
                return True
            if self._l2 is not None and self._l2.exists(full_key):
                return True
            if self._l3 is not None and self._l3.exists(full_key):
                return True
            return False
        except Exception as exc:
            logger.warning("Cache exists error for %s: %s", full_key, exc)
            return False

    def clear(self, namespace: str | None = None) -> int:
        """Clear cache entries. Returns total number of entries cleared."""
        total = 0
        removed_keys: builtins.set[str] = builtins.set()
        try:
            if namespace is not None:
                for backend in (self._l1, self._l2, self._l3):
                    if backend is None:
                        continue
                    keys = self._list_keys_for_namespace(backend, namespace)
                    for k in keys:
                        backend.delete(k)
                        total += 1
                        removed_keys.add(k)
            else:
                for backend in (self._l1, self._l2, self._l3):
                    if backend is not None:
                        total += backend.clear()
            return total
        except Exception as exc:
            logger.warning("Cache clear error: %s", exc)
            self._metrics.record_error()
            return total

    def _list_keys_for_namespace(self, backend: Any, namespace: str) -> builtins.set[str]:
        """Return active keys in a namespace from a given backend."""
        if hasattr(backend, "get_keys_by_namespace"):
            return builtins.set(backend.get_keys_by_namespace(namespace))
        if hasattr(backend, "get_by_namespace"):
            return builtins.set(entry["key"] for entry in backend.get_by_namespace(namespace))
        return builtins.set()

    def cleanup_expired(self) -> int:
        """Remove expired entries from all tiers. Returns total removed."""
        total = 0
        try:
            for backend in (self._l1, self._l2, self._l3):
                if backend is not None:
                    total += backend.cleanup_expired()
            if total:
                self._metrics.expirations += total
            return total
        except Exception as exc:
            logger.warning("Cleanup error: %s", exc)
            self._metrics.record_error()
            return total

    def get_stats(self) -> CacheStats:
        """Get aggregated cache statistics across all tiers."""
        stats = CacheStats(
            metrics=self._metrics,
            backend_type="multi-tier",
        )
        if self._l1 is not None:
            l1_stats = self._l1.get_stats()
            stats.l1_entries = int(
                l1_stats.get("active_entries", l1_stats.get("total_entries", 0)) or 0
            )
            stats.total_entries += stats.l1_entries
        if self._l2 is not None:
            l2_stats = self._l2.get_stats()
            if isinstance(l2_stats, dict):
                stats.l2_entries = int(
                    l2_stats.get("active_entries", l2_stats.get("total_entries", 0)) or 0
                )
                stats.total_entries += stats.l2_entries
            else:
                stats.l2_entries = l2_stats.active_entries
                stats = stats.merge(l2_stats)
        if self._l3 is not None:
            l3_stats = self._l3.get_stats()
            if isinstance(l3_stats, dict):
                l3_count = l3_stats.get("index_entries", l3_stats.get("total_entries", 0))
                stats.l3_entries = int(cast(Any, l3_count) or 0)
                stats.total_entries += stats.l3_entries
            else:
                stats.l3_entries = l3_stats.active_entries
                stats = stats.merge(l3_stats)
        stats.active_entries = stats.total_entries
        return stats

    def get_metrics(self) -> CacheMetrics:
        """Return runtime metrics from this tier manager."""
        return self._metrics

    def get_metrics_snapshot(self) -> dict[str, Any]:
        """Return metrics as a plain dict."""
        return self._metrics.snapshot()

    def get_efficiency_snapshot(self) -> dict[str, Any]:
        """Return cache efficiency telemetry for shared API consumers."""
        return build_cache_efficiency_snapshot(self)

    def reset_metrics(self) -> None:
        """Reset all metrics to zero."""
        self._metrics.reset()

    @property
    def config(self) -> Any:
        """Return the active configuration."""
        return self._config

    @property
    def metrics(self) -> CacheMetrics:
        """Return the metrics tracker."""
        return self._metrics

    @property
    def l1(self) -> MemoryBackend | None:
        """Return the L1 backend."""
        return self._l1

    @property
    def l2(self) -> SQLiteBackend | RedisBackend | None:
        """Return the L2 backend."""
        return self._l2

    @property
    def l3(self) -> FileBackend | None:
        """Return the L3 backend."""
        return self._l3

    @property
    def _redis(self) -> Any | None:
        """Return the underlying Redis client if L2 is Redis."""
        if self._config.enable_l2 and self._config.l2_backend == "redis" and self._l2 is not None:
            return getattr(self._l2, "_client", None)
        return None

    def close(self) -> None:
        """Close all backend connections and persist state."""
        l1_healthy = self._l1 is not None
        l2_healthy = False
        if self._l2 is not None:
            try:
                l2_healthy = True
            except Exception:
                pass
        l3_healthy = self._l3 is not None

        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            metrics.gauge("cache_backend_health", "L1/L2/L3 backend health status").set(
                (1.0 if l1_healthy else 0.0)
                + (2.0 if l2_healthy else 0.0)
                + (4.0 if l3_healthy else 0.0)
            )
        except Exception:
            pass

        logger.info(
            "Cache manager closing: L1=%s L2=%s L3=%s",
            "healthy" if l1_healthy else "missing/down",
            "healthy" if l2_healthy else "missing/down",
            "healthy" if l3_healthy else "missing/down",
        )

        if self._l1 is not None:
            self._l1.close()
        if self._l2 is not None:
            self._l2.close()
        if self._l3 is not None:
            self._l3.close()
        if self._lock_redis_client is not None:
            try:
                self._lock_redis_client.close()
            except Exception as exc:
                logger.debug("Redis lock client close failed: %s", exc)
            self._lock_redis_client = None
        logger.info("Cache manager closed")

    def acquire_distributed_lock(
        self,
        lock_name: str,
        *,
        ttl: int = 900,
        wait_timeout: float = 0.0,
        retry_interval: float = 0.25,
        namespace: str = "recon",
    ) -> str | None:
        """Acquire a Redis-backed distributed lock. Returns a token or None."""
        client = self._get_redis_lock_client()
        if client is None:
            return None

        key = self._distributed_lock_key(lock_name, namespace)
        token = __import__("uuid").uuid4().hex
        deadline = time.monotonic() + max(0.0, wait_timeout)
        ttl_seconds = max(1, int(ttl))
        retry_seconds = max(0.05, float(retry_interval))

        while True:
            try:
                if client.set(key, token, nx=True, ex=ttl_seconds):
                    return str(token)
            except Exception as exc:
                logger.warning("Redis distributed lock acquire failed for %s: %s", key, exc)
                return None

            if time.monotonic() >= deadline:
                return None
            time.sleep(retry_seconds)

    def release_distributed_lock(
        self,
        lock_name: str,
        token: str,
        *,
        namespace: str = "recon",
    ) -> bool:
        """Release a Redis distributed lock only if the token still owns it."""
        if not token:
            return False
        client = self._get_redis_lock_client()
        if client is None:
            return False

        key = self._distributed_lock_key(lock_name, namespace)
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("del", KEYS[1])
        end
        return 0
        """
        try:
            return bool(client.eval(script, 1, key, token))
        except Exception as exc:
            logger.warning("Redis distributed lock release failed for %s: %s", key, exc)
            return False

    def distributed_lock(
        self,
        lock_name: str,
        *,
        ttl: int = 900,
        wait_timeout: float = 0.0,
        retry_interval: float = 0.25,
        namespace: str = "recon",
    ) -> Any:
        """Context manager for a Redis-backed distributed lock."""
        token = self.acquire_distributed_lock(
            lock_name,
            ttl=ttl,
            wait_timeout=wait_timeout,
            retry_interval=retry_interval,
            namespace=namespace,
        )
        try:
            yield token
        finally:
            if token:
                self.release_distributed_lock(lock_name, token, namespace=namespace)

    def acquire_recon_lock(
        self,
        target: str,
        *,
        ttl: int = 3600,
        wait_timeout: float = 0.0,
    ) -> str | None:
        """Acquire the standard target-scoped recon lock."""
        return self.acquire_distributed_lock(
            f"target:{target}",
            ttl=ttl,
            wait_timeout=wait_timeout,
            namespace="recon",
        )

    def release_recon_lock(self, target: str, token: str) -> bool:
        """Release the standard target-scoped recon lock."""
        return self.release_distributed_lock(
            f"target:{target}",
            token,
            namespace="recon",
        )

    def _make_key(self, raw_key: str, namespace: str) -> str:
        """Create a fully qualified cache key."""
        return f"{namespace}:{raw_key}"

    def _backfill(
        self,
        target_backend: Any,
        source_backend: Any,
        full_key: str,
        value: Any,
        ttl: float | None,
        namespace: str,
    ) -> None:
        """Backfill a value from source_backend into target_backend."""
        if ttl is not None and ttl <= 0:
            return
        if hasattr(target_backend, "set_with_metadata"):
            target_backend.set_with_metadata(full_key, value, ttl=ttl, namespace=namespace)
        else:
            target_backend.set(full_key, value, ttl=ttl)

    def _write_to_tiers(
        self,
        full_key: str,
        value: Any,
        ttl: int | None,
        namespace: str,
        tags: builtins.set[str] | None,
        depends_on: builtins.set[str] | None,
        metadata: dict[str, Any] | None,
    ) -> None:
        """Write the value to all enabled tiers."""
        if self._l1 is not None:
            self._l1.set(full_key, value, ttl=ttl)
        if self._l2 is not None:
            if hasattr(self._l2, "set_with_metadata"):
                self._l2.set_with_metadata(
                    full_key,
                    value,
                    ttl=ttl,
                    tags=tags,
                    namespace=namespace,
                    depends_on=depends_on,
                    metadata=metadata,
                )
            else:
                self._l2.set(full_key, value, ttl=ttl)
        if self._l3 is not None:
            self._l3.set(full_key, value, ttl=ttl)

    def _get_ttl_remaining(self, backend: Any, full_key: str) -> float | None:
        """Return a backend key's remaining TTL when the backend exposes it."""
        ttl_getter = getattr(backend, "get_ttl_remaining", None)
        if not callable(ttl_getter):
            return None
        ttl = ttl_getter(full_key)
        if ttl is None:
            return None
        return max(0.0, float(ttl))

    def _distributed_lock_key(self, lock_name: str, namespace: str) -> str:
        raw = str(lock_name or "").strip().lower()
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw)[:160]
        return f"cache_lock:{namespace}:{safe}:{digest}"

    def _get_redis_lock_client(self) -> Any | None:
        """Return a Redis client suitable for distributed locking."""
        if isinstance(self._l2, RedisBackend):
            client = getattr(self._l2, "_client", None)
            if client is not None:
                return client

        if self._lock_redis_client is not None:
            return self._lock_redis_client

        if not self._config.redis_url:
            return None

        try:
            import redis

            self._lock_redis_client = redis.from_url(
                self._config.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
            )
            self._lock_redis_client.ping()
            return self._lock_redis_client
        except Exception as exc:
            logger.warning("Redis distributed locking unavailable: %s", exc)
            self._lock_redis_client = None
            return None
