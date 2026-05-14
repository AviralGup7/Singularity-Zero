from __future__ import annotations

"""Pydantic models for the cross-run caching layer.

Defines data models for cache entries, configuration, statistics, and keys
using Pydantic v2 for validation, serialization, and type safety.
"""


import hashlib
import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class CacheKeyType(StrEnum):
    """Type of cache key for categorization."""

    SCAN_RESULT = "scan_result"
    FINDING = "finding"
    URL_RESPONSE = "url_response"
    CONFIG = "config"
    METADATA = "metadata"
    CUSTOM = "custom"


class CacheKey(BaseModel):
    """Structured cache key with namespace isolation.

    Supports hierarchical key construction for per-target, per-stage,
    and global cache entries.

    Attributes:
        namespace: Top-level namespace (e.g., 'scan', 'recon', 'global').
        target: Optional target identifier for per-target isolation.
        stage: Optional pipeline stage (e.g., 'discovery', 'enumeration').
        identifier: Unique identifier within the namespace/target/stage.
        key_type: Categorization of the cached data type.
        version: Optional version string for cache invalidation.
    """

    namespace: str = Field(..., min_length=1, max_length=128)
    target: str | None = Field(default=None, max_length=512)
    stage: str | None = Field(default=None, max_length=128)
    identifier: str = Field(..., min_length=1, max_length=1024)
    key_type: CacheKeyType = Field(default=CacheKeyType.CUSTOM)
    version: str | None = Field(default=None, max_length=64)

    def to_string(self) -> str:
        """Convert the structured key to a flat string key.

        Returns:
            Colon-delimited string representation of the key components.
        """
        parts = [self.namespace]
        if self.target:
            parts.append(self.target)
        if self.stage:
            parts.append(self.stage)
        if self.version:
            parts.append(f"v{self.version}")
        parts.append(self.identifier)
        return ":".join(parts)

    @classmethod
    def from_string(cls, key_str: str) -> CacheKey:
        """Parse a flat string key back into a structured CacheKey.

        Args:
            key_str: Colon-delimited key string.

        Returns:
            Parsed CacheKey instance.
        """
        parts = key_str.split(":", 1)
        namespace = parts[0] if parts else "default"
        remainder = parts[1] if len(parts) > 1 else ""

        return cls(
            namespace=namespace,
            identifier=remainder or key_str,
        )

    def fingerprint(self) -> str:
        """Generate a SHA-256 fingerprint of the full key.

        Returns:
            16-character hex digest for compact key representation.
        """
        return hashlib.sha256(self.to_string().encode()).hexdigest()[:16]


class CacheEntry(BaseModel):
    """A single cache entry with metadata.

    Stores the cached value along with creation time, expiration,
    tags, and access tracking for LRU eviction.

    Attributes:
        key: The cache key string.
        value: The cached data (any JSON-serializable type).
        created_at: Unix timestamp when the entry was created.
        expires_at: Unix timestamp when the entry expires (None = no expiry).
        last_accessed: Unix timestamp of the most recent access.
        access_count: Number of times this entry has been retrieved.
        tags: Set of tags for tag-based invalidation.
        namespace: Namespace for isolation.
        size_bytes: Approximate serialized size in bytes.
        metadata: Additional key-value metadata.
        depends_on: Set of cache keys this entry depends on.
    """

    key: str = Field(..., min_length=1)
    value: Any
    created_at: float = Field(default_factory=time.time)
    expires_at: float | None = Field(default=None)
    last_accessed: float = Field(default_factory=time.time)
    access_count: int = Field(default=0)
    tags: set[str] = Field(default_factory=set)
    namespace: str = Field(default="default")
    size_bytes: int = Field(default=0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    depends_on: set[str] = Field(default_factory=set)

    @field_validator("tags", mode="before")
    @classmethod
    def _normalize_tags(cls, v: Any) -> set[str]:
        if isinstance(v, list):
            return set(v)
        if isinstance(v, set):
            return v
        if v is None:
            return set()
        return set(v)

    @field_validator("depends_on", mode="before")
    @classmethod
    def _normalize_depends(cls, v: Any) -> set[str]:
        if isinstance(v, list):
            return set(v)
        if isinstance(v, set):
            return v
        if v is None:
            return set()
        return set(v)

    @property
    def is_expired(self) -> bool:
        """Check if the entry has expired based on its TTL.

        Returns:
            True if expires_at is set and the current time has passed it.
        """
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    @property
    def age_seconds(self) -> float:
        """Return the age of the entry in seconds."""
        return time.time() - self.created_at

    @property
    def ttl_remaining(self) -> float | None:
        """Return remaining TTL in seconds, or None if no expiry.

        Returns:
            Seconds until expiration, 0 if already expired, or None.
        """
        if self.expires_at is None:
            return None
        remaining = self.expires_at - time.time()
        return max(0.0, remaining)

    def touch(self) -> None:
        """Update the last_accessed timestamp and increment access_count.

        Called on every cache hit to support LRU eviction tracking.
        """
        self.last_accessed = time.time()
        self.access_count += 1

    def compute_size(self) -> int:
        """Estimate the serialized size of the entry in bytes.

        Returns:
            Approximate byte size of the JSON-serialized value.
        """
        import json

        try:
            serialized = json.dumps(self.value)
            self.size_bytes = len(serialized.encode("utf-8"))
        except (TypeError, ValueError):
            self.size_bytes = 0
        return self.size_bytes


class CacheMetrics(BaseModel):
    """Runtime metrics for cache performance monitoring.

    Tracks hits, misses, evictions, and timing information
    for observability and tuning.

    Attributes:
        hits: Total number of cache hits.
        misses: Total number of cache misses.
        sets: Total number of cache set operations.
        deletes: Total number of cache delete operations.
        evictions: Total number of entries evicted.
        expirations: Total number of entries expired by TTL.
        errors: Total number of cache operation errors.
        total_get_time_ms: Cumulative time spent on get operations.
        total_set_time_ms: Cumulative time spent on set operations.
    """

    hits: int = Field(default=0)
    misses: int = Field(default=0)
    sets: int = Field(default=0)
    deletes: int = Field(default=0)
    evictions: int = Field(default=0)
    expirations: int = Field(default=0)
    errors: int = Field(default=0)
    total_get_time_ms: float = Field(default=0.0)
    total_set_time_ms: float = Field(default=0.0)

    @property
    def hit_rate(self) -> float:
        """Calculate the cache hit rate as a fraction.

        Returns:
            Hit rate between 0.0 and 1.0, or 0.0 if no accesses.
        """
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.hits / total

    @property
    def avg_get_time_ms(self) -> float:
        """Calculate average get operation time in milliseconds.

        Returns:
            Average time per get, or 0.0 if no gets performed.
        """
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.total_get_time_ms / total

    @property
    def avg_set_time_ms(self) -> float:
        """Calculate average set operation time in milliseconds.

        Returns:
            Average time per set, or 0.0 if no sets performed.
        """
        if self.sets == 0:
            return 0.0
        return self.total_set_time_ms / self.sets

    def record_hit(self, elapsed_ms: float = 0.0) -> None:
        """Record a cache hit with optional timing.

        Args:
            elapsed_ms: Time taken for the get operation in milliseconds.
        """
        self.hits += 1
        self.total_get_time_ms += elapsed_ms

    def record_miss(self, elapsed_ms: float = 0.0) -> None:
        """Record a cache miss with optional timing.

        Args:
            elapsed_ms: Time taken for the get operation in milliseconds.
        """
        self.misses += 1
        self.total_get_time_ms += elapsed_ms

    def record_set(self, elapsed_ms: float = 0.0) -> None:
        """Record a cache set operation with optional timing.

        Args:
            elapsed_ms: Time taken for the set operation in milliseconds.
        """
        self.sets += 1
        self.total_set_time_ms += elapsed_ms

    def record_delete(self) -> None:
        """Record a cache delete operation."""
        self.deletes += 1

    def record_eviction(self) -> None:
        """Record a cache eviction."""
        self.evictions += 1

    def record_expiration(self) -> None:
        """Record a TTL-based expiration."""
        self.expirations += 1

    def record_error(self) -> None:
        """Record a cache operation error."""
        self.errors += 1

    def reset(self) -> None:
        """Reset all metrics to zero."""
        self.hits = 0
        self.misses = 0
        self.sets = 0
        self.deletes = 0
        self.evictions = 0
        self.expirations = 0
        self.errors = 0
        self.total_get_time_ms = 0.0
        self.total_set_time_ms = 0.0

    def snapshot(self) -> dict[str, Any]:
        """Return a plain dict snapshot of all metrics.

        Returns:
            Dict with all metric field values.
        """
        return self.model_dump()


class CacheStats(BaseModel):
    """Aggregate statistics for the entire cache system.

    Provides a snapshot of cache state including entry counts,
    size information, and performance metrics.

    Attributes:
        total_entries: Total number of entries across all tiers.
        active_entries: Number of non-expired entries.
        expired_entries: Number of expired entries pending cleanup.
        total_size_bytes: Total serialized size of all entries.
        namespaces: Map of namespace to entry count.
        metrics: Runtime performance metrics.
        backend_info: Backend-specific status information.
        l1_entries: Number of entries in the L1 (memory) tier.
        l2_entries: Number of entries in the L2 (SQLite/Redis) tier.
        l3_entries: Number of entries in the L3 (file) tier.
    """

    total_entries: int = Field(default=0)
    active_entries: int = Field(default=0)
    expired_entries: int = Field(default=0)
    total_size_bytes: int = Field(default=0)
    namespaces: dict[str, int] = Field(default_factory=dict)
    metrics: CacheMetrics = Field(default_factory=CacheMetrics)
    backend_info: dict[str, Any] = Field(default_factory=dict)
    l1_entries: int = Field(default=0)
    l2_entries: int = Field(default=0)
    l3_entries: int = Field(default=0)
    backend_type: str = Field(default="multi-tier")

    def merge(self, other: CacheStats) -> CacheStats:
        """Merge statistics from another CacheStats instance.

        Args:
            other: Another CacheStats to merge with.

        Returns:
            New CacheStats with combined values.
        """
        return CacheStats(
            total_entries=self.total_entries + other.total_entries,
            active_entries=self.active_entries + other.active_entries,
            expired_entries=self.expired_entries + other.expired_entries,
            total_size_bytes=self.total_size_bytes + other.total_size_bytes,
            namespaces={**self.namespaces, **other.namespaces},
            metrics=self.metrics,
            backend_info={**self.backend_info, **other.backend_info},
            l1_entries=self.l1_entries + other.l1_entries,
            l2_entries=self.l2_entries + other.l2_entries,
            l3_entries=self.l3_entries + other.l3_entries,
        )
