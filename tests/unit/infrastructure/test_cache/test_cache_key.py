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



class TestCacheKey(unittest.TestCase):
    def test_to_string_minimal(self) -> None:
        key = CacheKey(namespace="scan", identifier="abc123")
        assert key.to_string() == "scan:abc123"

    def test_to_string_full(self) -> None:
        key = CacheKey(
            namespace="recon",
            target="example.com",
            stage="discovery",
            identifier="subdomains",
            key_type=CacheKeyType.SCAN_RESULT,
            version="2",
        )
        assert key.to_string() == "recon:example.com:discovery:v2:subdomains"

    def test_from_string(self) -> None:
        key = CacheKey.from_string("scan:abc123")
        assert key.namespace == "scan"
        assert key.identifier == "abc123"

    def test_fingerprint(self) -> None:
        key = CacheKey(namespace="scan", identifier="abc123")
        fp = key.fingerprint()
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_fingerprint_deterministic(self) -> None:
        k1 = CacheKey(namespace="scan", identifier="abc123")
        k2 = CacheKey(namespace="scan", identifier="abc123")
        assert k1.fingerprint() == k2.fingerprint()