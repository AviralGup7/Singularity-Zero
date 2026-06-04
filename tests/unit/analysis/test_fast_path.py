"""Unit tests for src.analysis.fast_path."""

import unittest

import pytest

from src.analysis.fast_path import (
    FastPathStats,
    FastPathDispatcher,
    _CACHE_HIT_KEY,
    _CACHE_MISS_KEY,
    _CACHE_TTL_SECONDS,
    _MAX_CACHE_SIZE,
    _RESPONSE_CACHE,
)


@pytest.mark.unit
class TestFastPathStats(unittest.TestCase):
    def test_default_values(self) -> None:
        s = FastPathStats()
        self.assertEqual(s.fast_path_count, 0)
        self.assertEqual(s.slow_path_count, 0)
        self.assertEqual(s.cache_hits, 0)
        self.assertEqual(s.cache_misses, 0)
        self.assertEqual(s.total_time_ms, 0.0)

    def test_to_dict_keys(self) -> None:
        s = FastPathStats()
        d = s.to_dict()
        for key in (
            "fast_path_count",
            "slow_path_count",
            "cache_hits",
            "cache_misses",
            "fast_path_ratio",
            "cache_hit_ratio",
            "total_requests",
            "total_time_ms",
            "avg_latency_ms",
        ):
            self.assertIn(key, d)

    def test_to_dict_zero_total(self) -> None:
        s = FastPathStats()
        d = s.to_dict()
        # max(total, 1) = 1 so ratios are 0
        self.assertEqual(d["fast_path_ratio"], 0.0)
        self.assertEqual(d["cache_hit_ratio"], 0.0)
        self.assertEqual(d["total_requests"], 0)

    def test_to_dict_with_counts(self) -> None:
        s = FastPathStats(fast_path_count=3, slow_path_count=1, cache_hits=2, total_time_ms=200.0)
        d = s.to_dict()
        self.assertEqual(d["fast_path_count"], 3)
        self.assertEqual(d["slow_path_count"], 1)
        self.assertEqual(d["cache_hits"], 2)
        self.assertEqual(d["total_requests"], 4)
        self.assertEqual(d["fast_path_ratio"], 0.75)
        self.assertEqual(d["avg_latency_ms"], 50.0)


@pytest.mark.unit
class TestFastPathDispatcherDefaults(unittest.TestCase):
    def test_default_construction(self) -> None:
        dispatcher = FastPathDispatcher()
        self.assertEqual(dispatcher._max_connections, 200)
        self.assertEqual(dispatcher._max_keepalive, 50)
        self.assertEqual(dispatcher._timeout, 10.0)
        self.assertFalse(dispatcher._http2)

    def test_custom_construction(self) -> None:
        dispatcher = FastPathDispatcher(
            max_connections=50,
            max_keepalive=10,
            timeout=5.0,
            http2=True,
        )
        self.assertEqual(dispatcher._max_connections, 50)
        self.assertEqual(dispatcher._max_keepalive, 10)
        self.assertEqual(dispatcher._timeout, 5.0)
        self.assertTrue(dispatcher._http2)

    def test_initial_stats(self) -> None:
        dispatcher = FastPathDispatcher()
        self.assertIsInstance(dispatcher.stats, FastPathStats)
        self.assertEqual(dispatcher.stats.fast_path_count, 0)


@pytest.mark.unit
class TestFastPathDispatcherStandardHeaders(unittest.TestCase):
    def test_standard_headers_populated(self) -> None:
        dispatcher = FastPathDispatcher()
        self.assertIn("User-Agent", dispatcher._standard_headers)
        self.assertIn("Accept", dispatcher._standard_headers)
        self.assertIn("Accept-Language", dispatcher._standard_headers)
        self.assertIn("Connection", dispatcher._standard_headers)

    def test_user_agent_is_chrome(self) -> None:
        dispatcher = FastPathDispatcher()
        ua = dispatcher._standard_headers["User-Agent"]
        self.assertIn("Chrome", ua)


@pytest.mark.unit
class TestClearCache(unittest.TestCase):
    def test_clear_cache_returns_count(self) -> None:
        # Manually populate global cache
        _RESPONSE_CACHE["test_key"] = {"status_code": 200}
        try:
            dispatcher = FastPathDispatcher()
            count = dispatcher.clear_cache()
            self.assertGreaterEqual(count, 1)
        finally:
            _RESPONSE_CACHE.clear()


@pytest.mark.unit
class TestModuleConstants(unittest.TestCase):
    def test_constants_present(self) -> None:
        self.assertEqual(_CACHE_HIT_KEY, "cache_hit")
        self.assertEqual(_CACHE_MISS_KEY, "cache_miss")
        self.assertEqual(_CACHE_TTL_SECONDS, 300)
        self.assertEqual(_MAX_CACHE_SIZE, 1000)


if __name__ == "__main__":
    unittest.main()
