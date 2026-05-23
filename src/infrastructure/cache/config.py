"""Configuration for the cross-run caching layer.

Defines CacheConfig with sensible defaults and environment variable
overrides for all cache parameters.
"""

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


def _env_int(name: str, default: int) -> int:
    """Read an integer from environment with a fallback.

    Args:
        name: Environment variable name.
        default: Default value if not set or invalid.

    Returns:
        Parsed integer or default.
    """
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError, TypeError:
        return default


def _env_float(name: str, default: float) -> float:
    """Read a float from environment with a fallback.

    Args:
        name: Environment variable name.
        default: Default value if not set or invalid.

    Returns:
        Parsed float or default.
    """
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return float(val)
    except ValueError, TypeError:
        return default


def _env_str(name: str, default: str) -> str:
    """Read a string from environment with a fallback.

    Args:
        name: Environment variable name.
        default: Default value if not set.

    Returns:
        Environment value or default.
    """
    return os.environ.get(name, default)


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean from environment with a fallback.

    Args:
        name: Environment variable name.
        default: Default value if not set.

    Returns:
        Parsed boolean or default.
    """
    val = os.environ.get(name)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes", "on")


class NamespaceTTL(BaseModel):
    """TTL configuration for a specific cache namespace.

    Attributes:
        ttl_seconds: Time-to-live in seconds for entries in this namespace.
        max_entries: Maximum number of entries before eviction triggers.
        enabled: Whether caching is enabled for this namespace.
    """

    ttl_seconds: int = Field(default=3600, ge=0)
    max_entries: int = Field(default=10000, ge=0)
    enabled: bool = Field(default=True)


class CacheConfig(BaseModel):
    """Master configuration for the caching layer.

    Controls all aspects of cache behavior including backends,
    TTL defaults, eviction policies, and persistence paths.

    Environment variables (all optional):
        CACHE_DEFAULT_TTL: Default TTL in seconds.
        CACHE_MAX_ENTRIES: Global max entry count.
        CACHE_DB_PATH: SQLite database file path.
        CACHE_DIR: Directory for file-based cache.
        CACHE_REDIS_URL: Redis connection URL.
        CACHE_LRU_EVICTION_RATIO: Fraction of entries to evict.

    Attributes:
        default_ttl: Default TTL in seconds for cache entries.
        max_entries: Global maximum number of entries per backend.
        lru_eviction_ratio: Fraction of entries to evict when at capacity.
        enable_l1: Enable L1 in-memory cache tier.
        enable_l2: Enable L2 persistent cache tier (SQLite or Redis).
        enable_l3: Enable L3 file-based cache tier.
        l2_backend: L2 backend type ('sqlite' or 'redis').
        sqlite_db_path: Path to the SQLite database file.
        redis_url: Redis connection URL (for RedisBackend).
        cache_dir: Base directory for file-based cache storage.
        namespace_ttls: Per-namespace TTL overrides.
        enable_compression: Enable gzip compression for file backend.
        warm_on_init: Load previous scan results into cache on init.
        warm_sources: Paths to scan result files for cache warming.
        tag_index_enabled: Enable tag-based indexing for invalidation.
        dependency_tracking: Enable dependency-based invalidation.
        version: Global cache version for bulk invalidation.
        metrics_enabled: Enable hit/miss metrics collection.
        cleanup_interval: Seconds between automatic expired entry cleanup.
    """

    default_ttl: int = Field(default=_env_int("CACHE_DEFAULT_TTL", 3600), ge=0)
    max_entries: int = Field(default=_env_int("CACHE_MAX_ENTRIES", 10000), ge=0)
    lru_eviction_ratio: float = Field(
        default=_env_float("CACHE_LRU_EVICTION_RATIO", 0.25),
        ge=0.0,
        le=1.0,
    )
    enable_l1: bool = Field(default=True)
    enable_l2: bool = Field(default=True)
    enable_l3: bool = Field(default=False)
    l2_backend: str = Field(default="sqlite", pattern="^(sqlite|redis)$")
    sqlite_db_path: str = Field(
        default=_env_str(
            "CACHE_DB_PATH",
            str(Path(__file__).resolve().parent.parent / "output" / "cache" / "cache_layer.db"),
        )
    )
    redis_url: str | None = Field(
        default=_env_str("CACHE_REDIS_URL", "redis://localhost:6379/0") or None
    )
    cache_dir: str = Field(
        default=_env_str(
            "CACHE_DIR",
            str(Path(__file__).resolve().parent.parent / "output" / "cache" / "files"),
        )
    )
    namespace_ttls: dict[str, NamespaceTTL] = Field(default_factory=dict)
    enable_compression: bool = Field(default=True)
    warm_on_init: bool = Field(default=False)
    warm_sources: list[str] = Field(default_factory=list)
    tag_index_enabled: bool = Field(default=True)
    dependency_tracking: bool = Field(default=True)
    version: str = Field(default="1")
    metrics_enabled: bool = Field(default=True)
    cleanup_interval: int = Field(default=300, ge=0)
    enabled: bool = Field(default=True)
    log_cache_ops: bool = Field(default=False)

    def is_namespace_enabled(self, namespace: str) -> bool:
        """Check if caching is enabled for a namespace.

        Args:
            namespace: The cache namespace.

        Returns:
            True if the namespace is enabled.
        """
        if not self.enabled:
            return False
        ns_config = self.namespace_ttls.get(namespace)
        if ns_config is not None:
            return ns_config.enabled
        return True

    def get_namespace_ttl(self, namespace: str) -> NamespaceTTL:
        """Get the TTL configuration for a specific namespace.

        Falls back to defaults if no namespace-specific config exists.

        Args:
            namespace: The cache namespace to look up.

        Returns:
            NamespaceTTL with the configured or default values.
        """
        if namespace in self.namespace_ttls:
            return self.namespace_ttls[namespace]
        return NamespaceTTL(
            ttl_seconds=self.default_ttl,
            max_entries=self.max_entries,
            enabled=True,
        )

    def model_post_init(self, __context: Any) -> None:
        """Ensure the cache directory exists after initialization."""
        Path(self.cache_dir).mkdir(parents=True, exist_ok=True)
        db_path = Path(self.sqlite_db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> dict[str, Any]:
        """Serialize config to a plain dictionary.

        Returns:
            Dict representation suitable for logging or persistence.
        """
        return self.model_dump()


def get_default_config() -> CacheConfig:
    """Create a CacheConfig with all defaults.

    Returns:
        CacheConfig instance with default values.
    """
    return CacheConfig()
