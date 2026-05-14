"""Unit tests for the cross-run caching layer."""

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


@pytest.mark.unit
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


@pytest.mark.unit
class TestCacheEntry(unittest.TestCase):
    def test_entry_defaults(self) -> None:
        entry = CacheEntry(key="k1", value="v1")
        assert entry.key == "k1"
        assert entry.value == "v1"
        assert entry.access_count == 0
        assert entry.tags == set()
        assert entry.depends_on == set()

    def test_entry_is_expired_false(self) -> None:
        entry = CacheEntry(key="k1", value="v1", expires_at=time.time() + 3600)
        assert entry.is_expired is False

    def test_entry_is_expired_true(self) -> None:
        entry = CacheEntry(key="k1", value="v1", expires_at=time.time() - 10)
        assert entry.is_expired is True

    def test_entry_no_expiry(self) -> None:
        entry = CacheEntry(key="k1", value="v1", expires_at=None)
        assert entry.is_expired is False

    def test_entry_age_seconds(self) -> None:
        entry = CacheEntry(key="k1", value="v1")
        time.sleep(0.01)
        assert entry.age_seconds > 0

    def test_entry_ttl_remaining(self) -> None:
        entry = CacheEntry(key="k1", value="v1", expires_at=time.time() + 100)
        remaining = entry.ttl_remaining
        assert 95 < remaining <= 100

    def test_entry_ttl_remaining_none(self) -> None:
        entry = CacheEntry(key="k1", value="v1", expires_at=None)
        assert entry.ttl_remaining is None

    def test_entry_touch(self) -> None:
        entry = CacheEntry(key="k1", value="v1")
        old_access = entry.last_accessed
        time.sleep(0.01)
        entry.touch()
        assert entry.last_accessed > old_access
        assert entry.access_count == 1

    def test_entry_compute_size(self) -> None:
        entry = CacheEntry(key="k1", value={"data": "test"})
        size = entry.compute_size()
        assert size > 0


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestMemoryBackend(unittest.TestCase):
    def test_set_and_get(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        assert backend.get("k1") == "v1"

    def test_get_missing(self) -> None:
        backend = MemoryBackend()
        assert backend.get("missing") is None

    def test_delete(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        assert backend.delete("k1") is True
        assert backend.get("k1") is None

    def test_delete_missing(self) -> None:
        backend = MemoryBackend()
        assert backend.delete("missing") is False

    def test_exists(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        assert backend.exists("k1") is True
        assert backend.exists("missing") is False

    def test_clear(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        count = backend.clear()
        assert count == 2
        assert backend.size() == 0

    def test_size(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        assert backend.size() == 2

    def test_ttl_expiry(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1", ttl=0)
        time.sleep(0.01)
        assert backend.get("k1") is None

    def test_cleanup_expired(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1", ttl=0)
        backend.set("k2", "v2", ttl=3600)
        time.sleep(0.01)
        removed = backend.cleanup_expired()
        assert removed == 1
        assert backend.get("k2") == "v2"

    def test_evict_lru(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        backend.set("k3", "v3")
        backend.get("k1")
        backend.get("k2")
        removed = backend.evict_lru(1)
        assert removed == 1

    def test_get_all(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        all_entries = backend.get_all()
        assert all_entries["k1"] == "v1"
        assert all_entries["k2"] == "v2"

    def test_get_stats(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        stats = backend.get_stats()
        assert stats["backend"] == "memory"
        assert stats["total_entries"] == 1

    def test_close(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        backend.close()
        assert backend.size() == 0


class CacheTestBase(unittest.TestCase):
    def setUp(self) -> None:
        from pathlib import Path

        self.tmp_path = Path(tempfile.mkdtemp())


@pytest.mark.unit
class TestSQLiteBackend(CacheTestBase):
    def test_set_and_get(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", {"data": "value"})
        assert backend.get("k1") == {"data": "value"}
        backend.close()

    def test_get_missing(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        assert backend.get("missing") is None
        backend.close()

    def test_delete(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1")
        assert backend.delete("k1") is True
        assert backend.get("k1") is None
        backend.close()

    def test_exists(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1")
        assert backend.exists("k1") is True
        assert backend.exists("missing") is False
        backend.close()

    def test_clear(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        count = backend.clear()
        assert count == 2
        backend.close()

    def test_size(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        assert backend.size() == 2
        backend.close()

    def test_ttl_expiry(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1", ttl=0)
        time.sleep(0.01)
        assert backend.get("k1") is None
        backend.close()

    def test_cleanup_expired(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1", ttl=0)
        backend.set("k2", "v2", ttl=3600)
        time.sleep(0.01)
        removed = backend.cleanup_expired()
        assert removed == 1
        backend.close()

    def test_get_stats(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        stats = backend.get_stats()
        assert stats["backend"] == "sqlite"
        backend.close()

    def test_get_by_namespace(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set_with_metadata("ns1:k1", "v1", namespace="ns1")
        results = backend.get_by_namespace("ns1")
        assert len(results) == 1
        backend.close()

    def test_get_by_tag(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set_with_metadata("k1", "v1", tags={"tag1", "tag2"})
        keys = backend.get_by_tag("tag1")
        assert "k1" in keys
        backend.close()

    def test_evict_lru(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        backend.get("k1")
        removed = backend.evict_lru(1)
        assert removed == 1
        backend.close()


@pytest.mark.unit
class TestFileBackend(CacheTestBase):
    def test_set_and_get(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", {"data": "value"})
        assert backend.get("k1") == {"data": "value"}
        backend.close()

    def test_get_missing(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        assert backend.get("missing") is None
        backend.close()

    def test_delete(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", "v1")
        assert backend.delete("k1") is True
        assert backend.get("k1") is None
        backend.close()

    def test_exists(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", "v1")
        assert backend.exists("k1") is True
        assert backend.exists("missing") is False
        backend.close()

    def test_clear(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        count = backend.clear()
        assert count == 2
        backend.close()

    def test_size(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", "v1")
        assert backend.size() == 1
        backend.close()

    def test_ttl_expiry(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", "v1", ttl=0)
        time.sleep(0.01)
        assert backend.get("k1") is None
        backend.close()

    def test_cleanup_expired(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", "v1", ttl=0)
        backend.set("k2", "v2", ttl=3600)
        time.sleep(0.01)
        removed = backend.cleanup_expired()
        assert removed == 1
        backend.close()

    def test_get_stats(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        stats = backend.get_stats()
        assert stats["backend"] == "file"
        backend.close()

    def test_get_keys_by_namespace(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("ns1:k1", "v1")
        backend.set("ns2:k2", "v2")
        keys = backend.get_keys_by_namespace("ns1")
        assert "ns1:k1" in keys
        backend.close()


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestTagInvalidation(unittest.TestCase):
    def test_invalidate_by_tag(self) -> None:
        strategy = TagInvalidation()
        store = {
            "k1": CacheEntry(key="k1", value="v1", tags={"a", "b"}),
            "k2": CacheEntry(key="k2", value="v2", tags={"b"}),
            "k3": CacheEntry(key="k3", value="v3", tags={"c"}),
        }
        strategy.register_entry("k1", {"a", "b"})
        strategy.register_entry("k2", {"b"})
        strategy.register_entry("k3", {"c"})
        removed = strategy.invalidate(store, tags={"a"})
        assert "k1" in removed
        assert "k2" not in removed

    def test_no_tags(self) -> None:
        strategy = TagInvalidation()
        store = {"k1": CacheEntry(key="k1", value="v1")}
        assert strategy.invalidate(store, tags=None) == []

    def test_get_keys_by_tag(self) -> None:
        strategy = TagInvalidation()
        strategy.register_entry("k1", {"tag1"})
        strategy.register_entry("k2", {"tag1"})
        strategy.register_entry("k3", {"tag2"})
        keys = strategy.get_keys_by_tag("tag1")
        assert "k1" in keys
        assert "k2" in keys
        assert "k3" not in keys

    def test_name(self) -> None:
        assert TagInvalidation().name() == "Tag"


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestCacheManager(CacheTestBase):
    def test_set_and_get(self) -> None:
        config = CacheConfig(
            enabled=True,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        manager.set("k1", "v1", namespace="test")
        assert manager.get("k1", namespace="test") == "v1"
        manager.close()

    def test_get_missing(self) -> None:
        config = CacheConfig(
            enabled=True,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        assert manager.get("missing", namespace="test") is None
        manager.close()

    def test_delete(self) -> None:
        config = CacheConfig(
            enabled=True,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        manager.set("k1", "v1", namespace="test")
        assert manager.delete("k1", namespace="test") is True
        assert manager.get("k1", namespace="test") is None
        manager.close()

    def test_exists(self) -> None:
        config = CacheConfig(
            enabled=True,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        manager.set("k1", "v1", namespace="test")
        assert manager.exists("k1", namespace="test") is True
        assert manager.exists("missing", namespace="test") is False
        manager.close()

    def test_clear_namespace(self) -> None:
        config = CacheConfig(
            enabled=True,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        manager.set("k1", "v1", namespace="ns1")
        manager.set("k2", "v2", namespace="ns1")
        count = manager.clear(namespace="ns1")
        assert count >= 1
        manager.close()

    def test_get_stats(self) -> None:
        config = CacheConfig(
            enabled=True,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        manager.set("k1", "v1", namespace="test")
        stats = manager.get_stats()
        assert isinstance(stats, CacheStats)
        manager.close()

    def test_get_metrics(self) -> None:
        config = CacheConfig(
            enabled=True,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        metrics = manager.get_metrics()
        assert isinstance(metrics, CacheMetrics)
        manager.close()

    def test_reset_metrics(self) -> None:
        config = CacheConfig(
            enabled=True,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        manager.metrics.record_hit()
        manager.reset_metrics()
        assert manager.metrics.hits == 0
        manager.close()

    def test_disabled_cache(self) -> None:
        config = CacheConfig(
            enabled=False,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        manager.set("k1", "v1", namespace="test")
        assert manager.get("k1", namespace="test") is None
        manager.close()

    def test_bump_version(self) -> None:
        config = CacheConfig(
            enabled=True,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        new_ver = manager.bump_version()
        assert new_ver == "2"
        manager.close()

    def test_cleanup_expired(self) -> None:
        config = CacheConfig(
            enabled=True,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        manager.set("k1", "v1", namespace="test", ttl=0)
        time.sleep(0.01)
        removed = manager.cleanup_expired()
        assert removed >= 0
        manager.close()

    def test_invalidate_by_tags_respects_namespace(self) -> None:
        config = CacheConfig(
            enabled=True,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        manager.set("tagged_ns1", "v1", namespace="ns1", tags={"group:test"})
        manager.set("tagged_ns2", "v2", namespace="ns2", tags={"group:test"})

        removed = manager.invalidate_by_tags({"group:test"}, namespace="ns1")

        assert "ns1:tagged_ns1" in removed
        assert "ns2:tagged_ns2" not in removed
        assert manager.get("tagged_ns1", namespace="ns1") is None
        assert manager.get("tagged_ns2", namespace="ns2") == "v2"
        manager.close()

    def test_invalidate_by_dependencies_accepts_unqualified_root(self) -> None:
        config = CacheConfig(
            enabled=True,
            enable_l1=True,
            enable_l2=True,
            enable_l3=False,
            l2_backend="sqlite",
            sqlite_db_path=str(self.tmp_path / "cache.db"),
            cache_dir=str(self.tmp_path / "cache_files"),
            warm_on_init=False,
            log_cache_ops=False,
        )
        manager = CacheManager(config)
        manager.set("root", "root-value", namespace="deps")
        manager.set("child", "child-value", namespace="deps", depends_on={"root"})

        removed = manager.invalidate_by_dependencies({"root"})

        assert "deps:root" in removed
        assert "deps:child" in removed
        assert manager.get("root", namespace="deps") is None
        assert manager.get("child", namespace="deps") is None
        manager.close()
