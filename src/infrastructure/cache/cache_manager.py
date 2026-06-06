"""Thin orchestrator for the multi-tier cache system.

CacheManager is now a thin wrapper around:
- :class:`TierManager` — L1/L2/L3 backend lifecycle and data paths.
- :class:`InvalidationEngine` — TTL/LRU/tag/dependency/version invalidation.
- Warming helpers — cache warm_from_json / warm_from_sqlite / warm_from_directory.
- :func:`src.infrastructure.cache.telemetry.build_cache_efficiency_snapshot` — telemetry.

No data-path logic remains here.  All reads/writes/deletes/clears are
delegated to TierManager so that tests and external consumers can swap or
mock tiers without crossing invalidation-domain boundaries.
"""

from __future__ import annotations

import builtins
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from src.infrastructure.cache.config import CacheConfig, get_default_config
from src.infrastructure.cache.invalidation import InvalidationEngine
from src.infrastructure.cache.models import CacheMetrics, CacheStats
from src.infrastructure.cache.telemetry import build_cache_efficiency_snapshot
from src.infrastructure.cache.tier_manager import TierManager
from src.infrastructure.cache.warming import (
    warm_from_directory,
    warm_from_json,
    warm_from_sqlite,
)

if TYPE_CHECKING:
    from src.core.frontier.bloom import NeuralBloomFilter
    from src.core.frontier.bloom_mesh import BloomMeshSynchronizer, NeuralBloomMesh

logger = logging.getLogger(__name__)


class CacheManager:
    """Multi-tier cache manager with cross-run persistence.

    CacheManager composes:
    - TierManager for L1/L2/L3 backend lifecycle and data-path operations.
    - InvalidationEngine for tag, dependency, version, TTL and LRU strategies.
    - Cache warming helpers to pre-populate the cache on startup.

    Read path: L1 -> L2 -> L3 (cascade on miss, backfill on hit)
    Write path: write-through to all enabled tiers via TierManager.
    """

    def __init__(self, config: CacheConfig | None = None) -> None:
        """Initialize the cache manager.

        Args:
            config: CacheConfig instance. Uses defaults if None.
        """
        self._config = config or get_default_config()
        self._tiers = TierManager(self._config)
        self._invalidation = InvalidationEngine(
            max_entries=self._config.max_entries,
            eviction_count=int(self._config.max_entries * self._config.lru_eviction_ratio),
            initial_version=self._config.version,
        )
        self._bloom_synchronizer: NeuralBloomMesh | None = None
        self._bloom_filter: NeuralBloomFilter | None = None

        if self._config.warm_on_init:
            self._warm_cache()

    def set_bloom_synchronizer(self, synchronizer: NeuralBloomMesh | BloomMeshSynchronizer) -> None:
        """Register the active Bloom mesh synchronizer."""
        self._bloom_synchronizer = synchronizer
        self._tiers.set_bloom_synchronizer(synchronizer)

    def is_redundant_query(self, key: str, namespace: str = "default") -> bool:
        """Check the Bloom routing path to reject redundant queries."""
        return self._tiers.is_redundant_query(key, namespace)

    def set_bloom_filter(self, bloom_filter: NeuralBloomFilter) -> None:
        """Register a direct Bloom filter."""
        self._bloom_filter = bloom_filter
        self._tiers.set_bloom_filter(bloom_filter)

    @property
    def bloom_filter(self) -> NeuralBloomFilter | None:
        """Resolve the active Bloom filter."""
        return self._tiers.bloom_filter

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
                warm_from_json(self._tiers, source_path)
            elif source_path.is_file() and source_path.suffix == ".db":
                warm_from_sqlite(self._tiers, str(source_path))
            elif source_path.is_dir():
                warm_from_directory(self._tiers, source_path)
            logger.info("Cache warmed from source: %s", source)

    def _make_key(self, raw_key: str, namespace: str) -> str:
        """Create a fully qualified cache key."""
        return self._tiers._make_key(raw_key, namespace)

    def _normalize_dependency_keys(
        self,
        depends_on: builtins.set[str] | None,
        namespace: str,
    ) -> builtins.set[str] | None:
        """Normalize dependency keys to fully qualified names."""
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
        keys: Any,
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

    def _set_backend_value(
        self,
        backend: Any,
        full_key: str,
        value: Any,
        *,
        ttl: float | None,
        namespace: str,
    ) -> None:
        """Backfill a backend while preserving remaining TTL when available."""
        if ttl is not None and ttl <= 0:
            return
        if hasattr(backend, "set_with_metadata"):
            backend.set_with_metadata(full_key, value, ttl=ttl, namespace=namespace)
        else:
            backend.set(full_key, value, ttl=ttl)

    def get(
        self,
        key: str,
        namespace: str = "default",
        default: Any | None = None,
    ) -> Any | None:
        """Retrieve a value from the cache hierarchy via TierManager."""
        return self._tiers.get(key, namespace, default)

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
        """Store a value in all enabled cache tiers via TierManager."""
        self._tiers.set(key, value, ttl, namespace, tags, depends_on, metadata)
        normalized_depends_on = self._normalize_dependency_keys(depends_on, namespace)
        full_key = self._make_key(key, namespace)
        self._invalidation.update_entry(full_key, tags, normalized_depends_on)

    def delete(self, key: str, namespace: str = "default") -> bool:
        """Delete a key from all cache tiers."""
        full_key = self._make_key(key, namespace)
        deleted = self._tiers.delete(key, namespace)
        if deleted:
            self._invalidation.unregister_entry(full_key)
        return deleted

    def exists(self, key: str, namespace: str = "default") -> bool:
        """Check if a key exists in any cache tier."""
        return self._tiers.exists(key, namespace)

    def clear(self, namespace: str | None = None) -> int:
        """Clear cache entries.

        For namespace-scoped clears we must still unregister keys from the
        invalidation index, so we fork here.
        """
        total = self._tiers.clear(namespace)
        return total

    def invalidate_by_tags(
        self, tags: builtins.set[str], namespace: str | None = None
    ) -> list[str]:
        """Invalidate all entries with the specified tags."""
        if not tags:
            return []
        try:
            indexed_keys: builtins.set[str] = builtins.set()
            for tag in tags:
                indexed_keys.update(self._invalidation.tag_strategy.get_keys_by_tag(tag))

            keys_to_invalidate = self._filter_keys_by_namespace(indexed_keys, namespace)
            if not keys_to_invalidate:
                return []

            if self._tiers._l1 is not None:
                self._delete_keys_from_backend(self._tiers._l1, keys_to_invalidate)
            if self._tiers._l2 is not None:
                self._delete_keys_from_backend(self._tiers._l2, keys_to_invalidate)
            if self._tiers._l3 is not None:
                self._delete_keys_from_backend(self._tiers._l3, keys_to_invalidate)

            for key in keys_to_invalidate:
                self._invalidation.unregister_entry(key)

            self._tiers._metrics.deletes += len(keys_to_invalidate)
            return sorted(keys_to_invalidate)
        except Exception as exc:
            logger.warning("Tag invalidation error: %s", exc)
            self._tiers._metrics.record_error()
            return []

    def invalidate_by_dependencies(self, keys: builtins.set[str]) -> list[str]:
        """Invalidate keys and all their dependents."""
        try:
            if not keys:
                return []

            dep_index = self._invalidation.dep_strategy.reverse_deps
            normalized_roots: builtins.set[str] = builtins.set()
            for root in keys:
                if ":" in root:
                    normalized_roots.add(root)
                else:
                    suffix = f":{root}"
                    for candidate in dep_index:
                        if candidate.endswith(suffix):
                            normalized_roots.add(candidate)
                    for version_keys in self._invalidation.version_strategy.version_index.values():
                        for candidate in version_keys:
                            if candidate.endswith(suffix):
                                normalized_roots.add(candidate)

            for backend in (self._tiers._l1, self._tiers._l2, self._tiers._l3):
                if backend is not None and hasattr(backend, "get_keys_matching_roots"):
                    normalized_roots.update(backend.get_keys_matching_roots(keys))

            keys_to_invalidate = self._invalidation.dep_strategy.collect_invalidation_set(
                normalized_roots
            )
            queue = list(keys_to_invalidate or normalized_roots)
            seen = set(queue)
            while queue:
                current = queue.pop(0)
                for backend in (self._tiers._l1, self._tiers._l2, self._tiers._l3):
                    if backend is None or not hasattr(backend, "get_dependents"):
                        continue
                    for dependent in backend.get_dependents(current):
                        if dependent not in seen:
                            seen.add(dependent)
                            queue.append(dependent)
            keys_to_invalidate = seen
            if not keys_to_invalidate:
                return []

            if self._tiers._l1 is not None:
                self._delete_keys_from_backend(self._tiers._l1, keys_to_invalidate)
            if self._tiers._l2 is not None:
                self._delete_keys_from_backend(self._tiers._l2, keys_to_invalidate)
            if self._tiers._l3 is not None:
                self._delete_keys_from_backend(self._tiers._l3, keys_to_invalidate)

            for key in keys_to_invalidate:
                self._invalidation.unregister_entry(key)

            self._tiers._metrics.deletes += len(keys_to_invalidate)
            return sorted(keys_to_invalidate)
        except Exception as exc:
            logger.warning("Dependency invalidation error: %s", exc)
            self._tiers._metrics.record_error()
            return []

    def bump_version(self) -> str:
        """Bump the global cache version. Returns the new version string."""
        new_version = self._invalidation.bump_version()
        self._config.version = new_version
        return new_version

    def cleanup_expired(self) -> int:
        """Remove expired entries from all tiers. Returns total removed."""
        return self._tiers.cleanup_expired()

    def get_stats(self) -> CacheStats:
        """Get aggregated cache statistics."""
        return self._tiers.get_stats()

    def get_metrics(self) -> CacheMetrics:
        """Return runtime metrics."""
        return self._tiers.get_metrics()

    def get_metrics_snapshot(self) -> dict[str, Any]:
        """Return metrics as a plain dict."""
        return self._tiers.get_metrics_snapshot()

    def get_efficiency_snapshot(self) -> dict[str, Any]:
        """Return cache efficiency telemetry for shared API consumers."""
        return build_cache_efficiency_snapshot(self._tiers)

    def reset_metrics(self) -> None:
        """Reset all metrics to zero."""
        self._tiers.reset_metrics()

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
        return self._tiers.metrics

    @property
    def l1(self) -> Any | None:
        """Return the L1 backend."""
        return self._tiers.l1

    @property
    def l2(self) -> Any | None:
        """Return the L2 backend."""
        return self._tiers.l2

    @property
    def l3(self) -> Any | None:
        """Return the L3 backend."""
        return self._tiers.l3

    @property
    def _redis(self) -> Any | None:
        """Return the underlying Redis client if L2 is Redis."""
        return self._tiers._redis

    def close(self) -> None:
        """Close all backend connections and persist state."""
        self._tiers.close()

    def acquire_recon_lock(
        self,
        target: str,
        *,
        ttl: int = 3600,
        wait_timeout: float = 0.0,
    ) -> str | None:
        """Acquire the standard target-scoped recon lock."""
        return self._tiers.acquire_recon_lock(
            target,
            ttl=ttl,
            wait_timeout=wait_timeout,
        )

    def release_recon_lock(self, target: str, token: str) -> bool:
        """Release the standard target-scoped recon lock."""
        return self._tiers.release_recon_lock(target, token)

    def __enter__(self) -> CacheManager:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception as exc:
            logger.debug("CacheManager.__del__ close failed: %s", exc)
