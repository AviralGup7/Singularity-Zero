"""Unit tests for src.dashboard.rate_limiter module."""

import asyncio
import time
import threading
import unittest
from unittest.mock import patch

import pytest

import src.dashboard.rate_limiter as _rl_module
from src.dashboard.rate_limiter import (
    InMemoryRateLimiter,
    RateLimitConfig,
    _WindowEntry,
    get_rate_limiter,
)


@pytest.mark.unit
class TestWindowEntry(unittest.TestCase):
    def test_prune_removes_old_timestamps(self) -> None:
        entry = _WindowEntry()
        now = time.monotonic()
        entry.timestamps = [now - 120, now - 90, now - 30, now - 5]
        entry.prune(60.0, now)
        self.assertEqual(len(entry.timestamps), 2)

    def test_prune_removes_all_when_all_old(self) -> None:
        entry = _WindowEntry()
        now = time.monotonic()
        entry.timestamps = [now - 200, now - 150, now - 100]
        entry.prune(60.0, now)
        self.assertEqual(entry.timestamps, [])

    def test_prune_removes_none_when_all_recent(self) -> None:
        entry = _WindowEntry()
        now = time.monotonic()
        entry.timestamps = [now - 10, now - 5, now - 1]
        entry.prune(60.0, now)
        self.assertEqual(len(entry.timestamps), 3)

    def test_prune_empty_list(self) -> None:
        entry = _WindowEntry()
        now = time.monotonic()
        entry.prune(60.0, now)
        self.assertEqual(entry.timestamps, [])

    def test_count_returns_correct_number(self) -> None:
        entry = _WindowEntry()
        now = time.monotonic()
        entry.timestamps = [now - 10, now - 5, now - 1]
        self.assertEqual(entry.count(60.0, now), 3)

    def test_count_prunes_before_counting(self) -> None:
        entry = _WindowEntry()
        now = time.monotonic()
        entry.timestamps = [now - 120, now - 5, now - 1]
        self.assertEqual(entry.count(60.0, now), 2)

    def test_record_appends_timestamp(self) -> None:
        entry = _WindowEntry()
        now = time.monotonic()
        entry.record(now)
        self.assertEqual(len(entry.timestamps), 1)
        self.assertAlmostEqual(entry.timestamps[0], now, delta=0.01)

    def test_prune_boundary_cutoff_excluded(self) -> None:
        entry = _WindowEntry()
        now = time.monotonic()
        cutoff = now - 60.0
        entry.timestamps = [cutoff - 0.001, cutoff + 0.001]
        entry.prune(60.0, now)
        self.assertEqual(len(entry.timestamps), 1)
        self.assertAlmostEqual(entry.timestamps[0], cutoff + 0.001, delta=0.01)


@pytest.mark.unit
class TestRateLimiterBasic(unittest.TestCase):
    def setUp(self) -> None:
        self.config = RateLimitConfig(window_seconds=60.0, default_limit=5)
        self.limiter = InMemoryRateLimiter(self.config)

    def test_first_request_allowed(self) -> None:
        allowed, remaining, retry_after = asyncio.run(
            self.limiter.check("client1", "/api/test")
        )
        self.assertTrue(allowed)
        self.assertIsNone(retry_after)

    def test_within_limit_all_allowed(self) -> None:
        for _ in range(5):
            allowed, _, _ = asyncio.run(self.limiter.check("client2", "/api/test"))
            self.assertTrue(allowed)

    def test_over_limit_blocked(self) -> None:
        for _ in range(5):
            asyncio.run(self.limiter.check("client3", "/api/test"))
        allowed, remaining, retry_after = asyncio.run(
            self.limiter.check("client3", "/api/test")
        )
        self.assertFalse(allowed)
        self.assertEqual(remaining, 0)

    def test_retry_after_is_positive(self) -> None:
        for _ in range(5):
            asyncio.run(self.limiter.check("client4", "/api/test"))
        _, _, retry_after = asyncio.run(self.limiter.check("client4", "/api/test"))
        self.assertIsNotNone(retry_after)
        self.assertGreater(retry_after, 0)


@pytest.mark.unit
class TestRateLimiterWindowBoundary(unittest.TestCase):
    @patch("time.monotonic")
    def test_requests_expire_after_window(self, mock_mono: unittest.mock.MagicMock) -> None:
        config = RateLimitConfig(window_seconds=60.0, default_limit=2)
        limiter = InMemoryRateLimiter(config)
        base = 1000.0
        mock_mono.return_value = base
        asyncio.run(limiter.check("c", "/api/x"))
        asyncio.run(limiter.check("c", "/api/x"))
        allowed, _, _ = asyncio.run(limiter.check("c", "/api/x"))
        self.assertFalse(allowed)
        mock_mono.return_value = base + 65.0
        allowed, _, _ = asyncio.run(limiter.check("c", "/api/x"))
        self.assertTrue(allowed)

    @patch("time.monotonic")
    def test_requests_still_within_window(self, mock_mono: unittest.mock.MagicMock) -> None:
        config = RateLimitConfig(window_seconds=60.0, default_limit=2)
        limiter = InMemoryRateLimiter(config)
        base = 1000.0
        mock_mono.return_value = base
        asyncio.run(limiter.check("c2", "/api/x"))
        asyncio.run(limiter.check("c2", "/api/x"))
        mock_mono.return_value = base + 30.0
        allowed, _, _ = asyncio.run(limiter.check("c2", "/api/x"))
        self.assertFalse(allowed)

    @patch("time.monotonic")
    def test_boundary_exact_window(self, mock_mono: unittest.mock.MagicMock) -> None:
        config = RateLimitConfig(window_seconds=10.0, default_limit=1)
        limiter = InMemoryRateLimiter(config)
        base = 500.0
        mock_mono.return_value = base
        asyncio.run(limiter.check("c3", "/api/x"))
        mock_mono.return_value = base + 10.5
        allowed, _, _ = asyncio.run(limiter.check("c3", "/api/x"))
        self.assertTrue(allowed)


@pytest.mark.unit
class TestRateLimiterRemaining(unittest.TestCase):
    def setUp(self) -> None:
        self.config = RateLimitConfig(window_seconds=60.0, default_limit=3)
        self.limiter = InMemoryRateLimiter(self.config)

    def test_remaining_full_capacity(self) -> None:
        _, remaining, _ = asyncio.run(self.limiter.check("r1", "/api/test"))
        self.assertEqual(remaining, 2)

    def test_remaining_decreases_after_requests(self) -> None:
        asyncio.run(self.limiter.check("r2", "/api/test"))
        _, remaining, _ = asyncio.run(self.limiter.check("r2", "/api/test"))
        self.assertEqual(remaining, 1)

    def test_remaining_zero_after_limit_exceeded(self) -> None:
        for _ in range(3):
            asyncio.run(self.limiter.check("r3", "/api/test"))
        _, remaining, _ = asyncio.run(self.limiter.check("r3", "/api/test"))
        self.assertEqual(remaining, 0)

    def test_remaining_does_not_go_negative(self) -> None:
        for _ in range(5):
            asyncio.run(self.limiter.check("r4", "/api/test"))
        _, remaining, _ = asyncio.run(self.limiter.check("r4", "/api/test"))
        self.assertGreaterEqual(remaining, 0)


@pytest.mark.unit
class TestRateLimiterSeparateEndpoints(unittest.TestCase):
    def setUp(self) -> None:
        self.config = RateLimitConfig(window_seconds=60.0, default_limit=1)
        self.limiter = InMemoryRateLimiter(self.config)

    def test_different_endpoints_tracked_separately(self) -> None:
        asyncio.run(self.limiter.check("client", "/api/alpha"))
        allowed, _, _ = asyncio.run(self.limiter.check("client", "/api/beta"))
        self.assertTrue(allowed)

    def test_different_clients_tracked_separately(self) -> None:
        asyncio.run(self.limiter.check("clientA", "/api/test"))
        allowed, _, _ = asyncio.run(self.limiter.check("clientB", "/api/test"))
        self.assertTrue(allowed)


@pytest.mark.unit
class TestRateLimiterDefaultLimits(unittest.TestCase):
    def test_default_limit_for_unknown_endpoint(self) -> None:
        config = RateLimitConfig(default_limit=42)
        self.assertEqual(config.get_limit_for_endpoint("/api/unknown"), 42)

    def test_default_endpoints_have_limits(self) -> None:
        config = RateLimitConfig()
        self.assertGreater(config.get_limit_for_endpoint("/api/jobs/start"), 0)
        self.assertGreater(config.get_limit_for_endpoint("/api/replay"), 0)


@pytest.mark.unit
class TestRateLimiterConcurrency(unittest.TestCase):
    def test_concurrent_access_thread_safe(self) -> None:
        config = RateLimitConfig(window_seconds=60.0, default_limit=100)
        limiter = InMemoryRateLimiter(config)
        results: list[bool] = []
        lock = threading.Lock()

        def _check() -> None:
            allowed, _, _ = asyncio.run(limiter.check("shared", "/api/test"))
            with lock:
                results.append(allowed)

        threads = [threading.Thread(target=_check) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 10)
        self.assertTrue(all(results))


@pytest.mark.unit
class TestRateLimiterCustomLimits(unittest.TestCase):
    def test_custom_window_seconds(self) -> None:
        config = RateLimitConfig(window_seconds=5.0, default_limit=2)
        limiter = InMemoryRateLimiter(config)
        asyncio.run(limiter.check("c", "/api/x"))
        asyncio.run(limiter.check("c", "/api/x"))
        allowed, _, _ = asyncio.run(limiter.check("c", "/api/x"))
        self.assertFalse(allowed)

    def test_empty_limits_uses_default(self) -> None:
        config = RateLimitConfig(default_limit=10, endpoint_limits={})
        self.assertEqual(config.get_limit_for_endpoint("/api/anything"), 10)


@pytest.mark.unit
class TestGetRateLimiter(unittest.TestCase):
    def test_returns_singleton(self) -> None:
        with patch.object(_rl_module, "_rate_limiter_instance", None):
            inst1 = get_rate_limiter(RateLimitConfig())
            inst2 = get_rate_limiter()
            self.assertIs(inst1, inst2)

    def test_returns_rate_limiter_instance(self) -> None:
        with patch.object(_rl_module, "_rate_limiter_instance", None):
            inst = get_rate_limiter(RateLimitConfig())
            self.assertIsInstance(inst, InMemoryRateLimiter)


if __name__ == "__main__":
    unittest.main()
