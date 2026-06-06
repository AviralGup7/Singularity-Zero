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



class TestVersionInvalidation(unittest.TestCase):
    def test_bump_version(self) -> None:
        strategy = VersionInvalidation(initial_version="1")
        new_ver = strategy.bump_version()
        assert new_ver == "2"

    def test_invalidate_old_versions(self) -> None:
        strategy = VersionInvalidation(initial_version="1")
        store = {
            "k1": CacheEntry(key="k1", value="v1"),
            "k2": CacheEntry(key="k2", value="v2"),
        }
        strategy.register_entry("k1", version="1")
        strategy.bump_version()
        removed = strategy.invalidate(store, all_old=True)
        assert "k1" in removed

    def test_name(self) -> None:
        assert VersionInvalidation().name() == "Version"