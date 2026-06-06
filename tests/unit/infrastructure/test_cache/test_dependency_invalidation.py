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



class TestDependencyInvalidation(unittest.TestCase):
    def test_cascade_invalidation(self) -> None:
        strategy = DependencyInvalidation()
        store = {
            "k1": CacheEntry(key="k1", value="v1"),
            "k2": CacheEntry(key="k2", value="v2", depends_on={"k1"}),
            "k3": CacheEntry(key="k3", value="v3"),
        }
        strategy.register_dependency("k2", {"k1"})
        removed = strategy.invalidate(store, keys={"k1"})
        assert "k1" in removed
        assert "k2" in removed
        assert "k3" not in removed

    def test_no_keys(self) -> None:
        strategy = DependencyInvalidation()
        store = {"k1": CacheEntry(key="k1", value="v1")}
        assert strategy.invalidate(store, keys=None) == []

    def test_name(self) -> None:
        assert DependencyInvalidation().name() == "Dependency"