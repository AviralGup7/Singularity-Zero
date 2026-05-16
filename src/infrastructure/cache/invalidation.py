"""Cache invalidation strategies for the caching layer.

Provides TTL-based, LRU, tag-based, dependency-based, and version-based
invalidation strategies that can be composed via the InvalidationEngine.
"""

import logging
import time
from abc import ABC, abstractmethod
from collections import deque
from typing import Any

from src.infrastructure.cache.models import CacheEntry, CacheMetrics

logger = logging.getLogger(__name__)


class InvalidationStrategy(ABC):
    """Abstract base class for cache invalidation strategies.

    Subclasses implement specific invalidation logic such as TTL
    expiration, LRU eviction, tag-based removal, etc.
    """

    @abstractmethod
    def invalidate(
        self,
        store: dict[str, CacheEntry],
        **kwargs: Any,
    ) -> list[str]:
        """Invalidate entries in the store.

        Args:
            store: The cache store dict mapping keys to CacheEntry objects.
            **kwargs: Strategy-specific parameters.

        Returns:
            List of keys that were invalidated.
        """
        ...

    @abstractmethod
    def name(self) -> str:
        """Return the name of this strategy.

        Returns:
            Human-readable strategy name.
        """
        ...


class TTLInvalidation(InvalidationStrategy):
    """Time-to-live based invalidation.

    Removes all entries whose expires_at timestamp has passed.
    This is the most common form of cache invalidation.
    """

    def invalidate(
        self,
        store: dict[str, CacheEntry],
        **kwargs: Any,
    ) -> list[str]:
        """Remove all expired entries.

        Args:
            store: The cache store dict.
            **kwargs: Unused.

        Returns:
            List of expired keys that were removed.
        """
        now = time.time()
        expired = [
            key
            for key, entry in store.items()
            if entry.expires_at is not None and now > entry.expires_at
        ]
        for key in expired:
            del store[key]
        if expired:
            logger.debug("TTL invalidation removed %d expired entries", len(expired))
        return expired

    def name(self) -> str:
        return "TTL"


class LRUInvalidation(InvalidationStrategy):
    """Least Recently Used eviction strategy.

    Evicts the least recently accessed entries when the cache exceeds
    a configurable maximum size.

    Attributes:
        max_entries: Maximum number of entries before eviction triggers.
        eviction_count: Number of entries to evict per cycle.
    """

    def __init__(self, max_entries: int = 10000, eviction_count: int | None = None) -> None:
        """Initialize the LRU invalidation strategy.

        Args:
            max_entries: Maximum entries before eviction.
            eviction_count: Number to evict when over limit.
                Defaults to 25% of max_entries.
        """
        self.max_entries = max_entries
        self.eviction_count = eviction_count or max(1, max_entries // 4)

    def invalidate(
        self,
        store: dict[str, CacheEntry],
        **kwargs: Any,
    ) -> list[str]:
        """Evict least recently used entries if over capacity.

        Args:
            store: The cache store dict.
            **kwargs: Unused.

        Returns:
            List of evicted keys.
        """
        if len(store) <= self.max_entries:
            return []
        over_by = len(store) - self.max_entries
        to_evict = max(over_by, self.eviction_count)
        sorted_keys = sorted(
            store.keys(),
            key=lambda k: store[k].last_accessed,
        )
        evict_keys = sorted_keys[:to_evict]
        for key in evict_keys:
            del store[key]
        if evict_keys:
            logger.debug(
                "LRU eviction removed %d entries (max=%d, was=%d)",
                len(evict_keys),
                self.max_entries,
                len(store) + len(evict_keys),
            )
        return evict_keys

    def name(self) -> str:
        return "LRU"


class TagInvalidation(InvalidationStrategy):
    """Tag-based invalidation.

    Removes all entries that have one or more of the specified tags.
    Useful for group invalidation (e.g., invalidate all entries for
    a specific target or scan).

    Attributes:
        tag_index: Dict mapping tags to sets of keys.
        key_index: Dict mapping keys to sets of tags.
    """

    def __init__(self) -> None:
        """Initialize the tag invalidation strategy."""
        self.tag_index: dict[str, set[str]] = {}
        self.key_index: dict[str, set[str]] = {}

    def register_entry(self, key: str, tags: set[str]) -> None:
        """Register an entry's tags in the index.

        Args:
            key: Cache key.
            tags: Set of tags for this entry.
        """
        existing_tags = self.key_index.get(key, set()).copy()
        for stale_tag in existing_tags - tags:
            if stale_tag in self.tag_index:
                self.tag_index[stale_tag].discard(key)
                if not self.tag_index[stale_tag]:
                    del self.tag_index[stale_tag]

        for tag in tags:
            if tag not in self.tag_index:
                self.tag_index[tag] = set()
            self.tag_index[tag].add(key)

        if tags:
            self.key_index[key] = set(tags)
        else:
            self.key_index.pop(key, None)

    def unregister_entry(self, key: str, tags: set[str] | None = None) -> None:
        """Remove an entry from the tag index.

        Args:
            key: Cache key.
            tags: Set of tags to remove the key from.
        """
        if tags is None:
            tags = self.key_index.get(key, set()).copy()

        for tag in tags:
            if tag in self.tag_index:
                self.tag_index[tag].discard(key)
                if not self.tag_index[tag]:
                    del self.tag_index[tag]

        self.key_index.pop(key, None)

    def invalidate(
        self,
        store: dict[str, CacheEntry],
        tags: set[str] | None = None,
        **kwargs: Any,
    ) -> list[str]:
        """Remove all entries with the specified tags.

        Args:
            store: The cache store dict.
            tags: Set of tags to invalidate. If None, no entries removed.
            **kwargs: Unused.

        Returns:
            List of invalidated keys.
        """
        if not tags:
            return []
        keys_to_remove: set[str] = set()
        for tag in tags:
            if tag in self.tag_index:
                keys_to_remove.update(self.tag_index[tag])
        keys_to_remove &= set(store.keys())
        for key in keys_to_remove:
            self.unregister_entry(key)
            del store[key]
        if keys_to_remove:
            logger.debug(
                "Tag invalidation removed %d entries for tags: %s",
                len(keys_to_remove),
                tags,
            )
        return sorted(keys_to_remove)

    def get_keys_by_tag(self, tag: str) -> list[str]:
        """Get all keys with a specific tag.

        Args:
            tag: Tag string.

        Returns:
            List of keys with the tag.
        """
        return sorted(self.tag_index.get(tag, set()))

    def get_tags_for_key(self, key: str) -> set[str]:
        """Get all tags currently associated with a key.

        Args:
            key: Cache key.

        Returns:
            A copy of tags associated with the key.
        """
        return self.key_index.get(key, set()).copy()

    def name(self) -> str:
        return "Tag"


class DependencyInvalidation(InvalidationStrategy):
    """Dependency-based invalidation.

    When an entry is invalidated, all entries that depend on it are
    also invalidated recursively. This ensures cache consistency
    when upstream data changes.

    Attributes:
        reverse_deps: Dict mapping keys to sets of dependent keys.
    """

    def __init__(self) -> None:
        """Initialize the dependency invalidation strategy."""
        self.reverse_deps: dict[str, set[str]] = {}

    def register_dependency(self, key: str, depends_on: set[str]) -> None:
        """Register that `key` depends on the given keys.

        Args:
            key: The dependent cache key.
            depends_on: Set of keys it depends on.
        """
        for dep in depends_on:
            if dep not in self.reverse_deps:
                self.reverse_deps[dep] = set()
            self.reverse_deps[dep].add(key)

    def unregister_key(self, key: str) -> None:
        """Remove a key from the dependency graph.

        Args:
            key: Cache key to remove.
        """
        for dep_key in self.reverse_deps.get(key, set()):
            if dep_key in self.reverse_deps:
                self.reverse_deps[dep_key].discard(key)
        self.reverse_deps.pop(key, None)
        for dep_set in self.reverse_deps.values():
            dep_set.discard(key)

    def collect_invalidation_set(self, keys: set[str] | None) -> set[str]:
        """Collect keys and all transitive dependents.

        Args:
            keys: Root keys to invalidate.

        Returns:
            Set of keys containing roots and all dependent keys.
        """
        if not keys:
            return set()

        all_to_remove: set[str] = set()
        queue: deque[str] = deque(keys)

        while queue:
            current = queue.popleft()
            if current in all_to_remove:
                continue

            all_to_remove.add(current)
            for dependent in self.reverse_deps.get(current, set()):
                if dependent not in all_to_remove:
                    queue.append(dependent)

        return all_to_remove

    def invalidate(
        self,
        store: dict[str, CacheEntry],
        keys: set[str] | None = None,
        **kwargs: Any,
    ) -> list[str]:
        """Invalidate keys and all their dependents recursively.

        Args:
            store: The cache store dict.
            keys: Set of root keys to invalidate.
            **kwargs: Unused.

        Returns:
            List of all invalidated keys (including dependents).
        """
        all_to_remove = self.collect_invalidation_set(keys)
        if not all_to_remove:
            return []

        all_to_remove &= set(store.keys())
        for key in all_to_remove:
            self.unregister_key(key)
            del store[key]
        if all_to_remove:
            logger.debug(
                "Dependency invalidation removed %d entries (roots: %d)",
                len(all_to_remove),
                len(keys) if keys is not None else 0,
            )
        return sorted(all_to_remove)

    def name(self) -> str:
        return "Dependency"


class VersionInvalidation(InvalidationStrategy):
    """Version-based invalidation.

    Associates a version string with the entire cache. When the version
    is bumped, all entries with the old version are invalidated.
    Useful for bulk invalidation when the data schema changes.

    Attributes:
        current_version: The current cache version.
        version_index: Dict mapping version strings to sets of keys.
    """

    def __init__(self, initial_version: str = "1") -> None:
        """Initialize the version invalidation strategy.

        Args:
            initial_version: Starting version string.
        """
        self.current_version = initial_version
        self.version_index: dict[str, set[str]] = {initial_version: set()}

    def register_entry(self, key: str, version: str | None = None) -> None:
        """Register an entry under a version.

        Args:
            key: Cache key.
            version: Version string. Defaults to current_version.
        """
        ver = version or self.current_version
        if ver not in self.version_index:
            self.version_index[ver] = set()
        self.version_index[ver].add(key)

    def bump_version(self) -> str:
        """Increment the cache version.

        Returns:
            The new version string.
        """
        parts = self.current_version.split(".")
        try:
            parts[-1] = str(int(parts[-1]) + 1)
        except ValueError:
            parts.append("1")
        self.current_version = ".".join(parts)
        if self.current_version not in self.version_index:
            self.version_index[self.current_version] = set()
        logger.info("Cache version bumped to %s", self.current_version)
        return self.current_version

    def set_version(self, version: str) -> None:
        """Set the cache version explicitly.

        Args:
            version: New version string.
        """
        self.current_version = version
        if version not in self.version_index:
            self.version_index[version] = set()

    def invalidate(
        self,
        store: dict[str, CacheEntry],
        version: str | None = None,
        all_old: bool = True,
        **kwargs: Any,
    ) -> list[str]:
        """Invalidate entries by version.

        Args:
            store: The cache store dict.
            version: Specific version to invalidate. If None and all_old
                is True, invalidates all entries not matching current version.
            all_old: If True and version is None, invalidate all non-current.
            **kwargs: Unused.

        Returns:
            List of invalidated keys.
        """
        keys_to_remove: set[str] = set()
        if version is not None:
            keys_to_remove = self.version_index.get(version, set()).copy()
        elif all_old:
            for ver, keys in self.version_index.items():
                if ver != self.current_version:
                    keys_to_remove.update(keys)
        keys_to_remove &= set(store.keys())
        for key in keys_to_remove:
            del store[key]
        for ver in list(self.version_index.keys()):
            self.version_index[ver] -= keys_to_remove
            if not self.version_index[ver] and ver != self.current_version:
                del self.version_index[ver]
        if keys_to_remove:
            logger.debug(
                "Version invalidation removed %d entries (version=%s)",
                len(keys_to_remove),
                version or "all_old",
            )
        return sorted(keys_to_remove)

    def name(self) -> str:
        return "Version"


class InvalidationEngine:
    """Composes multiple invalidation strategies into a unified engine.

    Coordinates TTL, LRU, tag, dependency, and version-based invalidation
    across the cache store. Provides a single interface for all
    invalidation operations.

    Attributes:
        strategies: Ordered list of registered strategies.
        tag_strategy: TagInvalidation instance for tag operations.
        dep_strategy: DependencyInvalidation instance for dependency ops.
        version_strategy: VersionInvalidation instance for version ops.
        metrics: Metrics tracker for invalidation operations.
    """

    def __init__(
        self,
        max_entries: int = 10000,
        eviction_count: int | None = None,
        initial_version: str = "1",
    ) -> None:
        """Initialize the invalidation engine.

        Args:
            max_entries: Maximum entries for LRU eviction.
            eviction_count: Number to evict per LRU cycle.
            initial_version: Starting cache version.
        """
        self._ttl_strategy = TTLInvalidation()
        self._lru_strategy = LRUInvalidation(max_entries, eviction_count)
        self._tag_strategy = TagInvalidation()
        self._dep_strategy = DependencyInvalidation()
        self._version_strategy = VersionInvalidation(initial_version)
        self._strategies: list[InvalidationStrategy] = [
            self._ttl_strategy,
            self._lru_strategy,
        ]
        self._metrics = CacheMetrics()

    @property
    def tag_strategy(self) -> TagInvalidation:
        """Return the tag invalidation strategy."""
        return self._tag_strategy

    @property
    def dep_strategy(self) -> DependencyInvalidation:
        """Return the dependency invalidation strategy."""
        return self._dep_strategy

    @property
    def version_strategy(self) -> VersionInvalidation:
        """Return the version invalidation strategy."""
        return self._version_strategy

    @property
    def current_version(self) -> str:
        """Return the current cache version."""
        return self._version_strategy.current_version

    def register_strategy(self, strategy: InvalidationStrategy) -> None:
        """Add a custom invalidation strategy.

        Args:
            strategy: Strategy instance to add.
        """
        self._strategies.append(strategy)

    def run_all(self, store: dict[str, CacheEntry]) -> dict[str, list[str]]:
        """Run all registered strategies in order.

        TTL runs first (remove expired), then LRU (evict if over capacity),
        then any custom strategies.

        Args:
            store: The cache store dict.

        Returns:
            Dict mapping strategy names to lists of invalidated keys.
        """
        results: dict[str, list[str]] = {}
        for strategy in self._strategies:
            invalidated = strategy.invalidate(store)
            results[strategy.name()] = invalidated
            self._metrics.evictions += len(invalidated)
        return results

    def invalidate_by_tags(
        self,
        store: dict[str, CacheEntry],
        tags: set[str],
    ) -> list[str]:
        """Invalidate entries by tags.

        Args:
            store: The cache store dict.
            tags: Set of tags to invalidate.

        Returns:
            List of invalidated keys.
        """
        result = self._tag_strategy.invalidate(store, tags=tags)
        self._metrics.deletes += len(result)
        return result

    def invalidate_by_dependencies(
        self,
        store: dict[str, CacheEntry],
        keys: set[str],
    ) -> list[str]:
        """Invalidate entries and their dependents.

        Args:
            store: The cache store dict.
            keys: Root keys to invalidate.

        Returns:
            List of all invalidated keys.
        """
        result = self._dep_strategy.invalidate(store, keys=keys)
        self._metrics.deletes += len(result)
        return result

    def invalidate_by_version(
        self,
        store: dict[str, CacheEntry],
        version: str | None = None,
        all_old: bool = True,
    ) -> list[str]:
        """Invalidate entries by version.

        Args:
            store: The cache store dict.
            version: Specific version to invalidate.
            all_old: Invalidate all non-current versions.

        Returns:
            List of invalidated keys.
        """
        result = self._version_strategy.invalidate(store, version=version, all_old=all_old)
        self._metrics.deletes += len(result)
        return result

    def bump_version(self) -> str:
        """Bump the cache version.

        Returns:
            The new version string.
        """
        return self._version_strategy.bump_version()

    def register_entry(
        self,
        key: str,
        tags: set[str] | None = None,
        depends_on: set[str] | None = None,
        version: str | None = None,
    ) -> None:
        """Register an entry with all relevant strategies.

        Called when a new entry is added to the cache.

        Args:
            key: Cache key.
            tags: Entry tags.
            depends_on: Entry dependencies.
            version: Entry version.
        """
        if tags:
            self._tag_strategy.register_entry(key, tags)
        if depends_on:
            self._dep_strategy.register_dependency(key, depends_on)
        self._version_strategy.register_entry(key, version)

    def unregister_entry(
        self,
        key: str,
        tags: set[str] | None = None,
    ) -> None:
        """Unregister an entry from tracking strategies.

        Called when an entry is removed from the cache.

        Args:
            key: Cache key.
            tags: Entry tags (for tag index cleanup).
        """
        if tags:
            self._tag_strategy.unregister_entry(key, tags)
        self._dep_strategy.unregister_key(key)

    def get_metrics(self) -> CacheMetrics:
        """Return invalidation metrics.

        Returns:
            CacheMetrics with eviction and deletion counts.
        """
        return self._metrics
