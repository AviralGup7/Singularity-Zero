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



class TestInvalidationEngine(unittest.TestCase):
    def test_run_all(self) -> None:
        engine = InvalidationEngine(max_entries=10)
        store = {"k1": CacheEntry(key="k1", value="v1", expires_at=time.time() - 10)}
        results = engine.run_all(store)
        assert "TTL" in results

    def test_invalidate_by_tags(self) -> None:
        engine = InvalidationEngine()
        store = {"k1": CacheEntry(key="k1", value="v1", tags={"t1"})}
        engine.register_entry("k1", tags={"t1"})
        removed = engine.invalidate_by_tags(store, {"t1"})
        assert "k1" in removed

    def test_invalidate_by_dependencies(self) -> None:
        engine = InvalidationEngine()
        store = {
            "k1": CacheEntry(key="k1", value="v1"),
            "k2": CacheEntry(key="k2", value="v2", depends_on={"k1"}),
        }
        engine.register_entry("k2", depends_on={"k1"})
        removed = engine.invalidate_by_dependencies(store, {"k1"})
        assert "k1" in removed
        assert "k2" in removed

    def test_bump_version(self) -> None:
        engine = InvalidationEngine(initial_version="1")
        new_ver = engine.bump_version()
        assert new_ver == "2"

    def test_get_metrics(self) -> None:
        engine = InvalidationEngine()
        metrics = engine.get_metrics()
        assert isinstance(metrics, CacheMetrics)