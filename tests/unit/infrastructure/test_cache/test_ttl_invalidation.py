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



class TestTTLInvalidation(unittest.TestCase):
    def test_remove_expired(self) -> None:
        strategy = TTLInvalidation()
        store = {
            "k1": CacheEntry(key="k1", value="v1", expires_at=time.time() - 10),
            "k2": CacheEntry(key="k2", value="v2", expires_at=time.time() + 3600),
        }
        removed = strategy.invalidate(store)
        assert "k1" in removed
        assert "k2" not in removed
        assert "k2" in store

    def test_no_expiry(self) -> None:
        strategy = TTLInvalidation()
        store = {"k1": CacheEntry(key="k1", value="v1")}
        removed = strategy.invalidate(store)
        assert removed == []

    def test_name(self) -> None:
        assert TTLInvalidation().name() == "TTL"