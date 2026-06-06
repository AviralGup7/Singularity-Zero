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



class TestLRUInvalidation(unittest.TestCase):
    def test_evict_when_over(self) -> None:
        strategy = LRUInvalidation(max_entries=2, eviction_count=1)
        store = {
            "k1": CacheEntry(key="k1", value="v1"),
            "k2": CacheEntry(key="k2", value="v2"),
            "k3": CacheEntry(key="k3", value="v3"),
        }
        removed = strategy.invalidate(store)
        assert len(removed) >= 1

    def test_no_evict_when_under(self) -> None:
        strategy = LRUInvalidation(max_entries=10)
        store = {"k1": CacheEntry(key="k1", value="v1")}
        removed = strategy.invalidate(store)
        assert removed == []

    def test_name(self) -> None:
        assert LRUInvalidation().name() == "LRU"