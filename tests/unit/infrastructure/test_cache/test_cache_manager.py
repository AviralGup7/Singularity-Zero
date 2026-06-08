import tempfile
import time
import unittest

import pytest

from src.infrastructure.cache.cache_manager import CacheManager
from src.infrastructure.cache.config import CacheConfig
from src.infrastructure.cache.models import (
    CacheMetrics,
    CacheStats,
)


class CacheTestBase(unittest.TestCase):
    def setUp(self) -> None:
        from pathlib import Path

        self.tmp_path = Path(tempfile.mkdtemp())

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

    def test_efficiency_snapshot_tracks_operations(self) -> None:
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
        manager.set("hit", "value", namespace="test", ttl=60)
        assert manager.get("hit", namespace="test") == "value"
        assert manager.get("miss", namespace="test") is None
        assert manager.delete("hit", namespace="test") is True

        snapshot = manager.get_efficiency_snapshot()

        assert snapshot["hits"] == 1
        assert snapshot["misses"] == 1
        assert snapshot["total_gets"] == 2
        assert snapshot["hit_ratio"] == pytest.approx(0.5)
        assert snapshot["sets"] == 1
        assert snapshot["deletes"] == 1
        assert snapshot["backend_errors"] == 0
        assert snapshot["avg_get_latency_ms"] >= 0.0
        assert snapshot["backend_type"] == "multi-tier"
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
        time.sleep(0.1)
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

    def test_tag_invalidation_survives_manager_restart(self) -> None:
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
        manager.set("tagged", "v1", namespace="persist", tags={"group:test"})
        manager.close()

        manager = CacheManager(config)
        removed = manager.invalidate_by_tags({"group:test"}, namespace="persist")

        assert removed == ["persist:tagged"]
        assert manager.get("tagged", namespace="persist") is None
        manager.close()

    def test_dependency_invalidation_survives_manager_restart(self) -> None:
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
        manager.close()

        manager = CacheManager(config)
        removed = manager.invalidate_by_dependencies({"root"})

        assert removed == ["deps:child", "deps:root"]
        assert manager.get("root", namespace="deps") is None
        assert manager.get("child", namespace="deps") is None
        manager.close()

    def test_l2_backfill_to_l1_preserves_remaining_ttl(self) -> None:
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
        manager.set("short", "value", namespace="ttl", ttl=0.1)
        manager.close()

        manager = CacheManager(config)
        assert manager.get("short", namespace="ttl") == "value"
        time.sleep(0.15)
        assert manager.get("short", namespace="ttl") is None
        manager.close()

    def test_bloom_aware_routing(self) -> None:
        from src.core.frontier.bloom import NeuralBloomFilter

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

        bf = NeuralBloomFilter(capacity=1000, error_rate=0.01)
        manager.set_bloom_filter(bf)

        assert manager.bloom_filter is bf

        assert manager.get("non_existent", namespace="test") is None

        manager.set("k1", "v1", namespace="test")
        full_key = manager._make_key("k1", "test")
        assert full_key in bf

        assert manager.get("k1", namespace="test") == "v1"

        assert manager.exists("non_existent", namespace="test") is False
        assert manager.exists("k1", namespace="test") is True

        manager.close()
