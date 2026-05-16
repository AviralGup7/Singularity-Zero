"""Main cache manager with multi-tier caching support.

Provides CacheManager which orchestrates L1 (memory), L2 (SQLite/Redis),
and L3 (file) cache tiers with configurable TTL, namespace isolation,
cache warming, and invalidation strategies.
"""

from __future__ import annotations

import builtins
import hashlib
import logging
import time
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from src.infrastructure.cache.backends import (
    FileBackend,
    MemoryBackend,
    RedisBackend,
    SQLiteBackend,
)
from src.infrastructure.cache.config import CacheConfig, get_default_config
from src.infrastructure.cache.invalidation import InvalidationEngine
from src.infrastructure.cache.models import CacheMetrics, CacheStats

from ._warmers import warm_from_directory, warm_from_json, warm_from_sqlite

logger = logging.getLogger(__name__)


class CacheManager:
    """Multi-tier cache manager with cross-run persistence.

    Manages a hierarchy of cache tiers:
        - L1: In-memory (MemoryBackend) - fastest, volatile
        - L2: SQLite or Redis (SQLiteBackend/RedisBackend) - persistent
        - L3: File-based (FileBackend) - archival, compatible with existing cache

    Read path: L1 -> L2 -> L3 (cascade on miss, backfill on hit)
    Write path: L1 + L2 + L3 (write-through to all enabled tiers)

    Features:
        - Configurable TTL per namespace
        - LRU eviction with configurable limits
        - Tag-based invalidation
        - Dependency-based invalidation
        - Version-based bulk invalidation
        - Cache warming from previous scan results
        - Namespace isolation (per-target, per-stage, global)
        - Hit/miss metrics collection
        - Thread-safe operations

    Attributes:
        config: Active CacheConfig instance.
        l1: L1 memory backend (or None if disabled).
        l2: L2 persistent backend (or None if disabled).
        l3: L3 file backend (or None if disabled).
        invalidation: InvalidationEngine for all strategies.
        metrics: Runtime metrics tracker.
    """

    def __init__(self, config: CacheConfig | None = None) -> None:
        """Initialize the cache manager.

        Args:
            config: CacheConfig instance. Uses defaults if None.
        """
        self._config = config or get_default_config()
        self._metrics = CacheMetrics()
        self._invalidation = InvalidationEngine(
            max_entries=self._config.max_entries,
            eviction_count=int(self._config.max_entries * self._config.lru_eviction_ratio),
            initial_version=self._config.version,
        )
        self._l1: MemoryBackend | None = None
        self._l2: SQLiteBackend | RedisBackend | None = None
        self._l3: FileBackend | None = None
        self._lock_redis_client: Any = None
        self._initialized = False
        self._init_backends()
        if self._config.warm_on_init:
            self._warm_cache()
        self._initialized = True

    def _init_backends(self) -> None:
        """Initialize enabled cache backends."""
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

    def _warm_cache(self) -> None:
        """Warm the cache from configured sources.

        Loads previous scan results into the cache for reuse.
        Sources can be JSON files, SQLite databases, or directories.
        """
        for source in self._config.warm_sources:
            source_path = Path(source)
            if not source_path.exists():
                logger.warning("Cache warm source not found: %s", source)
                continue
            if source_path.is_file() and source_path.suffix == ".json":
                warm_from_json(self, source_path)
            elif source_path.is_file() and source_path.suffix == ".db":
                warm_from_sqlite(self, str(source_path))
            elif source_path.is_dir():
                warm_from_directory(self, source_path)
            logger.info("Cache warmed from source: %s", source)

    # Warmers moved to src.infrastructure.cache._warmers

    def _make_key(self, raw_key: str, namespace: str) -> str:
        """Create a fully qualified cache key.

        Args:
            raw_key: The base key string.
            namespace: The namespace for isolation.

        Returns:
            Colon-separated qualified key string.
        """
        return f"{namespace}:{raw_key}"

    def _normalize_dependency_keys(
        self,
        depends_on: builtins.set[str] | None,
        namespace: str,
    ) -> builtins.set[str] | None:
        """Normalize dependency keys to fully qualified names.

        Unqualified dependency keys are interpreted in the same namespace as
        the entry being written.
        """
        if not depends_on:
            return None

        normalized: builtins.set[str] = builtins.set()
        for dep in depends_on:
            if ":" in dep:
                normalized.add(dep)
            else:
                normalized.add(self._make_key(dep, namespace))
        return normalized

    def _filter_keys_by_namespace(
        self,
        keys: Iterable[str],
        namespace: str | None,
    ) -> builtins.set[str]:
        """Filter keys to a namespace when provided."""
        key_set = builtins.set(keys)
        if namespace is None:
            return key_set

        prefix = f"{namespace}:"
        return {key for key in key_set if key.startswith(prefix)}

    def _delete_keys_from_backend(self, backend: Any, keys: builtins.set[str]) -> None:
        """Delete a key set from a backend, preferring batch operations."""
        if not keys:
            return

        if hasattr(backend, "delete_many"):
            backend.delete_many(keys)
            return

        for key in keys:
            backend.delete(key)

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

    def acquire_distributed_lock(
        self,
        lock_name: str,
        *,
        ttl: int = 900,
        wait_timeout: float = 0.0,
        retry_interval: float = 0.25,
        namespace: str = "recon",
    ) -> str | None:
        """Acquire a Redis-backed distributed lock.

        Returns a lock token when acquired. The token must be supplied to
        :meth:`release_distributed_lock`; a missing token means another worker
        owns the lock or Redis is unavailable.
        """
        client = self._get_redis_lock_client()
        if client is None:
            return None

        key = self._distributed_lock_key(lock_name, namespace)
        token = uuid4().hex
        deadline = time.monotonic() + max(0.0, wait_timeout)
        ttl_seconds = max(1, int(ttl))
        retry_seconds = max(0.05, float(retry_interval))

        while True:
            try:
                if client.set(key, token, nx=True, ex=ttl_seconds):
                    return token
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

    @contextmanager
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

    def get(
        self,
        key: str,
        namespace: str = "default",
        default: Any | None = None,
    ) -> Any | None:
        """Retrieve a value from the cache hierarchy.

        Checks L1 first, then L2, then L3. On a hit in a lower tier,
        the value is backfilled to higher tiers.

        Args:
            key: The cache key.
            namespace: Logical namespace for isolation.
            default: Value to return if the key is not found.

        Returns:
            Cached value, or default if not found.
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
                    if self._l1 is not None:
                        self._l1.set(full_key, value)
                    if self._config.log_cache_ops:
                        logger.debug("L2 HIT (backfilled to L1): %s", full_key)
                    return value

            if self._l3 is not None:
                value = self._l3.get(full_key)
                if value is not None:
                    elapsed = (time.monotonic() - start) * 1000
                    self._metrics.record_hit(elapsed)
                    if self._l1 is not None:
                        self._l1.set(full_key, value)
                    if self._config.log_cache_ops:
                        logger.debug("L3 HIT (backfilled to L1): %s", full_key)
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
        """Store a value in all enabled cache tiers.

        Uses write-through strategy: the value is written to all
        enabled tiers simultaneously.

        Args:
            key: The cache key.
            value: JSON-serializable value to cache.
            ttl: Time-to-live in seconds. Uses namespace default if None.
            namespace: Logical namespace for isolation.
            tags: Set of tags for group invalidation.
            depends_on: Set of keys this entry depends on.
            metadata: Arbitrary metadata dict.
        """
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

        normalized_depends_on = self._normalize_dependency_keys(depends_on, namespace)

        full_key = self._make_key(key, namespace)

        try:
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
                        depends_on=normalized_depends_on,
                        metadata=metadata,
                    )
                else:
                    self._l2.set(full_key, value, ttl=ttl)

            if self._l3 is not None:
                self._l3.set(full_key, value, ttl=ttl)

            # Re-register to prevent stale tag/dependency index entries on overwrite.
            self._invalidation.unregister_entry(full_key)
            self._invalidation.register_entry(full_key, tags, normalized_depends_on)
            if self._config.log_cache_ops:
                logger.debug("SET: %s (ttl=%ds, tags=%s)", full_key, ttl, tags)
        except Exception as exc:
            logger.warning("Cache set error for %s: %s", full_key, exc)
            self._metrics.record_error()

    def delete(self, key: str, namespace: str = "default") -> bool:
        """Delete a key from all cache tiers.

        Args:
            key: The cache key.
            namespace: The namespace.

        Returns:
            True if the key was found and deleted in any tier.
        """
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
            if deleted:
                self._invalidation.unregister_entry(full_key)
            return deleted
        except Exception as exc:
            logger.warning("Cache delete error for %s: %s", full_key, exc)
            self._metrics.record_error()
            return deleted

    def exists(self, key: str, namespace: str = "default") -> bool:
        """Check if a key exists in any cache tier.

        Args:
            key: The cache key.
            namespace: The namespace.

        Returns:
            True if the key exists in any tier.
        """
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
        """Clear cache entries.

        Args:
            namespace: If provided, clear only this namespace.
                If None, clear all tiers entirely.

        Returns:
            Total number of entries cleared.
        """
        total = 0
        removed_keys: builtins.set[str] = builtins.set()
        try:
            if namespace is not None:
                keys_l1 = []
                if self._l1:
                    if hasattr(self._l1, "get_keys_by_namespace"):
                        keys_l1 = self._l1.get_keys_by_namespace(namespace)
                    elif hasattr(self._l1, "get_by_namespace"):
                        keys_l1 = [entry["key"] for entry in self._l1.get_by_namespace(namespace)]
                for k in keys_l1:
                    if self._l1:
                        self._l1.delete(k)
                        total += 1
                        removed_keys.add(k)
                keys_l2 = []
                if self._l2:
                    if hasattr(self._l2, "get_keys_by_namespace"):
                        keys_l2 = self._l2.get_keys_by_namespace(namespace)
                    elif hasattr(self._l2, "get_by_namespace"):
                        keys_l2 = [entry["key"] for entry in self._l2.get_by_namespace(namespace)]
                for k in keys_l2:
                    if self._l2:
                        self._l2.delete(k)
                        total += 1
                        removed_keys.add(k)
                keys_l3 = []
                if self._l3:
                    if hasattr(self._l3, "get_keys_by_namespace"):
                        keys_l3 = self._l3.get_keys_by_namespace(namespace)
                    elif hasattr(self._l3, "get_by_namespace"):
                        keys_l3 = [entry["key"] for entry in self._l3.get_by_namespace(namespace)]
                for k in keys_l3:
                    if self._l3:
                        self._l3.delete(k)
                        total += 1
                        removed_keys.add(k)
            else:
                if self._l1 is not None:
                    total += self._l1.clear()
                if self._l2 is not None:
                    total += self._l2.clear()
                if self._l3 is not None:
                    total += self._l3.clear()

                # Full clear resets all index state for tags/dependencies/versions.
                self._invalidation = InvalidationEngine(
                    max_entries=self._config.max_entries,
                    eviction_count=int(self._config.max_entries * self._config.lru_eviction_ratio),
                    initial_version=self._config.version,
                )

            for removed_key in removed_keys:
                self._invalidation.unregister_entry(removed_key)

            return total
        except Exception as exc:
            logger.warning("Cache clear error: %s", exc)
            self._metrics.record_error()
            return total

    def invalidate_by_tags(self, tags: builtins.set[str], namespace: str | None = None) -> list[str]:
        """Invalidate all entries with the specified tags.

        Args:
            tags: Set of tags to invalidate.
            namespace: If provided, limit to this namespace.

        Returns:
            List of invalidated keys.
        """
        if not tags:
            return []

        try:
            indexed_keys: builtins.set[str] = builtins.set()
            for tag in tags:
                indexed_keys.update(self._invalidation.tag_strategy.get_keys_by_tag(tag))

            keys_to_invalidate = self._filter_keys_by_namespace(indexed_keys, namespace)
            if not keys_to_invalidate:
                return []

            if self._l1 is not None:
                self._delete_keys_from_backend(self._l1, keys_to_invalidate)
            if self._l2 is not None:
                self._delete_keys_from_backend(self._l2, keys_to_invalidate)
            if self._l3 is not None:
                self._delete_keys_from_backend(self._l3, keys_to_invalidate)

            for key in keys_to_invalidate:
                self._invalidation.unregister_entry(key)

            return sorted(keys_to_invalidate)
        except Exception as exc:
            logger.warning("Tag invalidation error: %s", exc)
            self._metrics.record_error()
            return []

    def invalidate_by_dependencies(self, keys: builtins.set[str]) -> list[str]:
        """Invalidate keys and all their dependents.

        Args:
            keys: Root keys to invalidate.

        Returns:
            List of all invalidated keys.
        """
        try:
            if not keys:
                return []

            dep_index = self._invalidation.dep_strategy.reverse_deps
            normalized_roots: builtins.set[str] = builtins.set()
            for root in keys:
                normalized_roots.add(root)
                if ":" not in root:
                    suffix = f":{root}"
                    for candidate in dep_index:
                        if candidate.endswith(suffix):
                            normalized_roots.add(candidate)

            keys_to_invalidate = self._invalidation.dep_strategy.collect_invalidation_set(
                normalized_roots
            )
            if not keys_to_invalidate:
                return []

            if self._l1 is not None:
                self._delete_keys_from_backend(self._l1, keys_to_invalidate)
            if self._l2 is not None:
                self._delete_keys_from_backend(self._l2, keys_to_invalidate)
            if self._l3 is not None:
                self._delete_keys_from_backend(self._l3, keys_to_invalidate)

            for key in keys_to_invalidate:
                self._invalidation.unregister_entry(key)

            return sorted(keys_to_invalidate)
        except Exception as exc:
            logger.warning("Dependency invalidation error: %s", exc)
            self._metrics.record_error()
            return []

    def bump_version(self) -> str:
        """Bump the global cache version.

        Entries with the old version will be invalidated on next access.

        Returns:
            The new version string.
        """
        new_version = self._invalidation.bump_version()
        self._config.version = new_version
        return new_version

    def cleanup_expired(self) -> int:
        """Remove expired entries from all tiers.

        Returns:
            Total number of expired entries removed.
        """
        total = 0
        try:
            if self._l1 is not None:
                total += self._l1.cleanup_expired()
            if self._l2 is not None:
                total += self._l2.cleanup_expired()
            if self._l3 is not None:
                total += self._l3.cleanup_expired()
            return total
        except Exception as exc:
            logger.warning("Cleanup error: %s", exc)
            self._metrics.record_error()
            return total

    def get_stats(self) -> CacheStats:
        """Get aggregated cache statistics.

        Returns:
            CacheStats with combined metrics from all tiers.
        """
        stats = CacheStats(
            metrics=self._metrics,
            backend_type="multi-tier",
        )
        if self._l1 is not None:
            l1_stats = self._l1.get_stats()
            stats.l1_entries = int(l1_stats.get("active_entries", l1_stats.get("total_entries", 0)) or 0)
            stats.total_entries += stats.l1_entries
        if self._l2 is not None:
            l2_stats = self._l2.get_stats()
            if isinstance(l2_stats, dict):
                stats.l2_entries = int(l2_stats.get("active_entries", l2_stats.get("total_entries", 0)) or 0)
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
        """Return runtime metrics.

        Returns:
            CacheMetrics with hit/miss counts and timing.
        """
        return self._metrics

    def get_metrics_snapshot(self) -> dict[str, Any]:
        """Return metrics as a plain dict.

        Returns:
            Dict with all metric values.
        """
        return self._metrics.snapshot()

    def reset_metrics(self) -> None:
        """Reset all metrics to zero."""
        self._metrics.reset()

    @property
    def config(self) -> CacheConfig:
        """Return the active configuration."""
        return self._config

    @property
    def invalidation(self) -> InvalidationEngine:
        """Return the invalidation engine."""
        return self._invalidation

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

    def close(self) -> None:
        """Close all backend connections and persist state."""
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

    def __enter__(self) -> CacheManager:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception as exc:
            logger.debug("CacheManager.__del__ close failed: %s", exc)
