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



class TestCacheMetrics(unittest.TestCase):
    def test_defaults(self) -> None:
        m = CacheMetrics()
        assert m.hits == 0
        assert m.misses == 0
        assert m.hit_rate == 0.0

    def test_hit_rate(self) -> None:
        m = CacheMetrics()
        m.record_hit()
        m.record_hit()
        m.record_miss()
        assert m.hit_rate == pytest.approx(2 / 3)

    def test_record_operations(self) -> None:
        m = CacheMetrics()
        m.record_hit(1.5)
        m.record_miss(2.0)
        m.record_set(0.5)
        m.record_delete()
        m.record_eviction()
        m.record_expiration()
        m.record_error()
        assert m.hits == 1
        assert m.misses == 1
        assert m.sets == 1
        assert m.deletes == 1
        assert m.evictions == 1
        assert m.expirations == 1
        assert m.errors == 1

    def test_avg_get_time(self) -> None:
        m = CacheMetrics()
        m.record_hit(10.0)
        m.record_miss(20.0)
        assert m.avg_get_time_ms == 15.0

    def test_avg_set_time(self) -> None:
        m = CacheMetrics()
        m.record_set(5.0)
        m.record_set(15.0)
        assert m.avg_set_time_ms == 10.0

    def test_reset(self) -> None:
        m = CacheMetrics(hits=10, misses=5, sets=3)
        m.reset()
        assert m.hits == 0
        assert m.misses == 0
        assert m.sets == 0

    def test_snapshot(self) -> None:
        m = CacheMetrics(hits=5)
        snap = m.snapshot()
        assert snap["hits"] == 5
        assert snap["total_gets"] == 5
        assert snap["hit_ratio"] == 1.0
        assert snap["backend_errors"] == 0

    def test_efficiency_snapshot_fields(self) -> None:
        m = CacheMetrics(hits=3, misses=1, sets=2, deletes=1, evictions=1, expirations=1)
        m.record_error()
        snapshot = build_cache_efficiency_snapshot(
            metrics=m,
            stats={
                "backend": "memory",
                "total_entries": 4,
                "active_entries": 3,
                "expired_entries": 1,
                "healthy": True,
            },
        )
        assert snapshot["subsystem"] == "cache"
        assert snapshot["backend_type"] == "memory"
        assert snapshot["hits"] == 3
        assert snapshot["misses"] == 1
        assert snapshot["total_gets"] == 4
        assert snapshot["hit_ratio"] == pytest.approx(0.75)
        assert snapshot["sets"] == 2
        assert snapshot["deletes"] == 1
        assert snapshot["evictions"] == 1
        assert snapshot["expirations"] == 1
        assert snapshot["backend_errors"] == 1
        assert snapshot["backend_health"]["healthy"] is True