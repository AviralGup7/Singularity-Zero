"""Cross-run caching layer for the cyber security test pipeline.

Provides multi-tier caching, configurable TTL, namespace isolation,
and multiple storage backends (SQLite, Redis, File, Memory).
"""

from src.infrastructure.cache.backends import (
    CacheBackend,
    FileBackend,
    MemoryBackend,
    RedisBackend,
    SQLiteBackend,
)
from src.infrastructure.cache.cache_manager import CacheManager
from src.infrastructure.cache.config import CacheConfig, get_default_config
from src.infrastructure.cache.invalidation import (
    DependencyInvalidation,
    InvalidationEngine,
    InvalidationStrategy,
    LRUInvalidation,
    TagInvalidation,
    TTLInvalidation,
    VersionInvalidation,
)
from src.infrastructure.cache.models import CacheEntry, CacheKey, CacheMetrics, CacheStats

__all__ = [
    "CacheConfig",
    "get_default_config",
    "CacheEntry",
    "CacheKey",
    "CacheStats",
    "CacheMetrics",
    "CacheBackend",
    "SQLiteBackend",
    "RedisBackend",
    "FileBackend",
    "MemoryBackend",
    "CacheManager",
    "InvalidationStrategy",
    "TTLInvalidation",
    "LRUInvalidation",
    "TagInvalidation",
    "DependencyInvalidation",
    "VersionInvalidation",
    "InvalidationEngine",
]
