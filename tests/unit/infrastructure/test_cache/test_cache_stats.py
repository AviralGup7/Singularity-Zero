import tempfile
import time
import unittest
import pytest
from src.infrastructure.cache.backends import FileBackend, MemoryBackend, SQLiteBackend
from src.infrastructure.cache.cache_manager import CacheManager
from src.infrastructure.cache.config import CacheConfig
from src.infrastructure.cache.invalidation import (
    DependencyInvalidation,
    InvalidationEngine,
    LRUInvalidation,
    TagInvalidation,
    TTLInvalidation,
    VersionInvalidation,
)
from src.infrastructure.cache.models import (
    CacheEntry,
    CacheKey,
    CacheKeyType,
    CacheMetrics,
    CacheStats,
)
from src.infrastructure.cache.telemetry import build_cache_efficiency_snapshot



class TestCacheStats(unittest.TestCase):
    def test_defaults(self) -> None:
        s = CacheStats()
        assert s.total_entries == 0
        assert s.active_entries == 0

    def test_merge(self) -> None:
        s1 = CacheStats(total_entries=10, l1_entries=5)
        s2 = CacheStats(total_entries=20, l2_entries=15)
        merged = s1.merge(s2)
        assert merged.total_entries == 30
        assert merged.l1_entries == 5
        assert merged.l2_entries == 15