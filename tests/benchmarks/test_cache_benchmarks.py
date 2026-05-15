"""Cache layer performance benchmarks.

Measures L1/L2/L3 read/write latency, hit/miss ratios, invalidation
performance, and memory usage of the multi-tier cache system
(cache_layer package).
"""

import json
import random
import tempfile
from pathlib import Path

import pytest


class TestCacheReadLatency:
    """Benchmark cache read operations across tiers."""

    def test_l1_read_latency(self, cache_manager, benchmark):
        """Measure L1 (memory) cache read latency."""
        for i in range(1000):
            cache_manager.set(
                f"key_{i}",
                {"data": f"value_{i}"},
                namespace="benchmark",
            )

        def _read_l1():
            return cache_manager.get("key_500", namespace="benchmark")

        result = benchmark(_read_l1)
        assert result is not None

    def test_l2_read_latency_sqlite(self, cache_manager, benchmark):
        """Measure L2 (SQLite) cache read latency on L1 miss."""
        if cache_manager.l1:
            cache_manager.l1.clear()

        for i in range(500):
            cache_manager.set(
                f"sqlite_key_{i}",
                {"data": f"value_{i}"},
                namespace="benchmark",
            )

        def _read_l2():
            return cache_manager.get("sqlite_key_250", namespace="benchmark")

        result = benchmark(_read_l2)
        assert result is not None

    def test_l1_miss_then_l2_hit(self, cache_manager, benchmark):
        """Measure L1 miss + L2 hit + backfill latency."""
        for i in range(500):
            cache_manager.set(
                f"backfill_{i}",
                {"data": f"value_{i}"},
                namespace="benchmark",
            )

        if cache_manager.l1:
            cache_manager.l1.clear()

        def _read_backfill():
            return cache_manager.get("backfill_100", namespace="benchmark")

        result = benchmark(_read_backfill)
        assert result is not None

    def test_cache_miss_latency(self, cache_manager, benchmark):
        """Measure cache miss latency (all tiers)."""

        def _miss():
            return cache_manager.get(
                "nonexistent_key",
                namespace="benchmark",
                default="default_value",
            )

        result = benchmark(_miss)
        assert result == "default_value"

    def test_exists_check_latency(self, cache_manager, benchmark):
        """Measure cache exists check latency."""
        for i in range(500):
            cache_manager.set(f"exists_{i}", i, namespace="benchmark")

        def _exists():
            return cache_manager.exists("exists_250", namespace="benchmark")

        result = benchmark(_exists)
        assert result is True


class TestCacheWriteThroughput:
    """Benchmark cache write operations."""

    def test_write_single_latency(self, cache_manager, benchmark):
        """Measure single write latency."""

        def _write():
            cache_manager.set(
                "write_test",
                {"data": "benchmark_value"},
                namespace="benchmark",
                ttl=3600,
            )

        benchmark(_write)

    def test_write_batch_100(self, cache_manager, benchmark):
        """Measure write throughput for 100 entries."""

        def _write_batch():
            for i in range(100):
                cache_manager.set(
                    f"batch_{i}",
                    {"data": "x" * 100, "index": i},
                    namespace="benchmark",
                    ttl=3600,
                )

        benchmark(_write_batch)

    def test_write_batch_1000(self, cache_manager, benchmark):
        """Measure write throughput for 1000 entries."""

        def _write_batch():
            for i in range(1000):
                cache_manager.set(
                    f"batch_large_{i}",
                    {"data": "x" * 50, "index": i},
                    namespace="benchmark",
                    ttl=3600,
                )

        benchmark(_write_batch)

    def test_write_with_tags(self, cache_manager, benchmark):
        """Measure write latency with tag indexing."""

        def _write_tagged():
            for i in range(100):
                cache_manager.set(
                    f"tagged_{i}",
                    {"value": i},
                    namespace="benchmark",
                    tags={"target:example.com", "stage:recon"},
                )

        benchmark(_write_tagged)

    def test_write_with_dependencies(self, cache_manager, benchmark):
        """Measure write latency with dependency tracking."""
        cache_manager.set("root_key", {"data": "root"}, namespace="benchmark")

        def _write_dependent():
            cache_manager.set(
                "dependent_key",
                {"data": "dependent"},
                namespace="benchmark",
                depends_on={"root_key"},
            )

        benchmark(_write_dependent)

    @pytest.mark.parametrize("payload_size", [100, 1000, 10000])
    def test_write_payload_size_impact(self, cache_manager, benchmark, payload_size):
        """Measure write latency with varying payload sizes."""
        payload = {"data": "x" * payload_size}

        def _write():
            cache_manager.set(
                f"size_test_{payload_size}",
                payload,
                namespace="benchmark",
            )

        benchmark(_write)


class TestCacheHitRatio:
    """Benchmark cache hit/miss ratios under realistic patterns."""

    def test_hot_key_pattern(self, cache_manager, benchmark):
        """Measure hit ratio with 80/20 hot/cold access pattern."""
        for i in range(1000):
            cache_manager.set(
                f"data_{i}",
                {"value": i},
                namespace="simulation",
            )

        hot_keys = [f"data_{i}" for i in range(200)]
        cold_keys = [f"data_{i}" for i in range(200, 1000)]

        cache_manager.reset_metrics()

        def _access_pattern():
            hits = 0
            for _ in range(500):
                if random.random() < 0.8:
                    key = random.choice(hot_keys)
                else:
                    key = random.choice(cold_keys)
                result = cache_manager.get(key, namespace="simulation")
                if result is not None:
                    hits += 1
            return hits

        benchmark(_access_pattern)
        metrics = cache_manager.get_metrics()
        hit_rate = metrics.hit_rate
        print(f"\nCache hit ratio (80/20): {hit_rate:.2%}")
        assert hit_rate > 0.7

    def test_sequential_access_pattern(self, cache_manager, benchmark):
        """Measure hit ratio with sequential access pattern."""
        for i in range(500):
            cache_manager.set(
                f"seq_{i}",
                {"value": i},
                namespace="sequential",
            )

        cache_manager.reset_metrics()

        def _sequential_access():
            hits = 0
            for i in range(200):
                result = cache_manager.get(f"seq_{i}", namespace="sequential")
                if result is not None:
                    hits += 1
            return hits

        benchmark(_sequential_access)
        metrics = cache_manager.get_metrics()
        print(f"\nSequential hit ratio: {metrics.hit_rate:.2%}")


class TestCacheInvalidation:
    """Benchmark cache invalidation performance."""

    def test_single_key_delete(self, cache_manager, benchmark):
        """Measure single key deletion latency."""

        def _setup():
            cache_manager.set("delete_me", {"data": "test"}, namespace="benchmark")

        def _delete():
            return cache_manager.delete("delete_me", namespace="benchmark")

        benchmark.pedantic(_delete, setup=_setup, rounds=100, iterations=1)

    def test_tag_invalidation_100(self, cache_manager, benchmark):
        """Measure tag-based invalidation for 100 entries."""

        def _setup():
            for i in range(100):
                cache_manager.set(
                    f"tag_inv_{i}",
                    {"value": i},
                    namespace="invalidation",
                    tags={"target:test.com"},
                )

        def _invalidate():
            return cache_manager.invalidate_by_tags({"target:test.com"})

        benchmark.pedantic(_invalidate, setup=_setup, rounds=100, iterations=1)

    def test_tag_invalidation_500(self, cache_manager, benchmark):
        """Measure tag-based invalidation for 500 entries."""

        def _setup():
            for i in range(500):
                cache_manager.set(
                    f"tag_inv_large_{i}",
                    {"value": i},
                    namespace="invalidation",
                    tags={"target:large.com", "stage:scan"},
                )

        def _invalidate():
            return cache_manager.invalidate_by_tags({"target:large.com"})

        benchmark.pedantic(_invalidate, setup=_setup, rounds=50, iterations=1)

    def test_version_bump_invalidation(self, cache_manager, benchmark):
        """Measure version bump invalidation speed."""
        for i in range(500):
            cache_manager.set(
                f"versioned_{i}",
                {"value": i},
                namespace="versioned",
            )

        def _bump_version():
            return cache_manager.bump_version()

        result = benchmark(_bump_version)
        assert result is not None

    def test_dependency_invalidation(self, cache_manager, benchmark):
        """Measure dependency-based invalidation."""

        def _setup():
            cache_manager.set("root", {"data": "root"}, namespace="deps")
            for i in range(50):
                cache_manager.set(
                    f"dep_{i}",
                    {"value": i},
                    namespace="deps",
                    depends_on={"root"},
                )

        def _invalidate_deps():
            return cache_manager.invalidate_by_dependencies({"root"})

        benchmark.pedantic(_invalidate_deps, setup=_setup, rounds=50, iterations=1)


class TestCacheWarmup:
    """Benchmark cache warmup performance."""

    def test_warmup_from_json_500(self, cache_manager, benchmark):
        """Measure warmup time from JSON file with 500 entries."""
        warm_data = {
            f"scan_result_{i}": {"finding": f"vuln_{i}", "severity": "high"} for i in range(500)
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(warm_data, f)
            warm_path = f.name

        try:
            from src.infrastructure.cache.config import CacheConfig

            warm_config = CacheConfig(
                enable_l1=True,
                enable_l2=True,
                warm_on_init=True,
                warm_sources=[warm_path],
            )

            def _warm():
                from src.infrastructure.cache import CacheManager

                mgr = CacheManager(warm_config)
                mgr.close()

            benchmark(_warm)
        finally:
            Path(warm_path).unlink(missing_ok=True)

    def test_warmup_from_json_5000(self, cache_manager, benchmark):
        """Measure warmup time from JSON file with 5000 entries."""
        warm_data = {
            f"scan_{i}": {
                "finding": f"vuln_{i}",
                "severity": random.choice(["low", "medium", "high", "critical"]),
            }
            for i in range(5000)
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(warm_data, f)
            warm_path = f.name

        try:
            from src.infrastructure.cache.config import CacheConfig

            warm_config = CacheConfig(
                enable_l1=True,
                enable_l2=True,
                warm_on_init=True,
                warm_sources=[warm_path],
            )

            def _warm():
                from src.infrastructure.cache import CacheManager

                mgr = CacheManager(warm_config)
                mgr.close()

            benchmark(_warm)
        finally:
            Path(warm_path).unlink(missing_ok=True)


class TestCacheCleanup:
    """Benchmark cache cleanup operations."""

    def test_cleanup_expired(self, cache_manager, benchmark):
        """Measure expired entry cleanup performance."""
        for i in range(500):
            cache_manager.set(
                f"expire_{i}",
                {"value": i},
                namespace="cleanup",
                ttl=1,
            )

        import time

        time.sleep(1.1)

        def _cleanup():
            return cache_manager.cleanup_expired()

        result = benchmark(_cleanup)
        assert result >= 0

    def test_clear_namespace(self, cache_manager, benchmark):
        """Measure namespace clear performance."""

        def _setup():
            for i in range(500):
                cache_manager.set(
                    f"clear_{i}",
                    {"value": i},
                    namespace="clear_test",
                )

        def _clear():
            return cache_manager.clear(namespace="clear_test")

        result = benchmark.pedantic(_clear, setup=_setup, rounds=50, iterations=1)
        assert result > 0

    def test_clear_all(self, cache_manager, benchmark):
        """Measure full cache clear performance."""

        def _setup():
            cache_manager.clear()
            for i in range(200):
                cache_manager.set(f"all_{i}", i, namespace="clear_all")

        def _clear_all():
            return cache_manager.clear()

        result = benchmark.pedantic(_clear_all, setup=_setup, rounds=50, iterations=1)
        assert result > 0


class TestCacheStats:
    """Benchmark cache statistics retrieval."""

    def test_get_stats(self, cache_manager, benchmark):
        """Measure stats retrieval latency."""
        for i in range(500):
            cache_manager.set(f"stats_{i}", i, namespace="stats")

        def _get_stats():
            return cache_manager.get_stats()

        result = benchmark(_get_stats)
        assert result is not None

    def test_get_metrics_snapshot(self, cache_manager, benchmark):
        """Measure metrics snapshot latency."""
        for i in range(200):
            cache_manager.get(f"stats_{i}", namespace="stats")

        def _snapshot():
            return cache_manager.get_metrics_snapshot()

        result = benchmark(_snapshot)
        assert "hits" in result
