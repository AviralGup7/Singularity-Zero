"""Unit tests for dashboard_app.server._rate_limiter module."""


# RateLimiter removed with legacy server — tests disabled

import unittest
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.skip(reason="RateLimiter removed with legacy server")


@pytest.mark.unit
class TestWindowEntry(unittest.TestCase):
    def test_prune_removes_old_timestamps(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_prune_removes_all_when_all_old(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_prune_removes_none_when_all_recent(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_prune_empty_list(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_count_returns_correct_number(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_count_prunes_before_counting(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_record_appends_timestamp(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_prune_boundary_cutoff_excluded(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")


@pytest.mark.unit
class TestRateLimiterBasic(unittest.TestCase):
    def test_first_request_allowed(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_within_limit_all_allowed(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_over_limit_blocked(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_retry_after_is_positive(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")


@pytest.mark.unit
class TestRateLimiterWindowBoundary(unittest.TestCase):
    @patch("time.monotonic")
    def test_requests_expire_after_window(self, mock_mono: unittest.mock.MagicMock) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    @patch("time.monotonic")
    def test_requests_still_within_window(self, mock_mono: unittest.mock.MagicMock) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    @patch("time.monotonic")
    def test_boundary_exact_window(self, mock_mono: unittest.mock.MagicMock) -> None:
        pytest.skip("RateLimiter removed with legacy server")


@pytest.mark.unit
class TestRateLimiterRemaining(unittest.TestCase):
    def test_remaining_full_capacity(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_remaining_decreases_after_requests(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_remaining_zero_after_limit_exceeded(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_remaining_does_not_go_negative(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")


@pytest.mark.unit
class TestRateLimiterSeparateEndpoints(unittest.TestCase):
    def test_different_endpoints_tracked_separately(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_different_clients_tracked_separately(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")


@pytest.mark.unit
class TestRateLimiterDefaultLimits(unittest.TestCase):
    def test_default_limit_for_unknown_endpoint(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_default_endpoints_have_limits(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")


@pytest.mark.unit
class TestRateLimiterConcurrency(unittest.TestCase):
    def test_concurrent_access_thread_safe(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")


@pytest.mark.unit
class TestRateLimiterCustomLimits(unittest.TestCase):
    def test_custom_window_seconds(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_empty_limits_uses_default(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")


@pytest.mark.unit
class TestGetRateLimiter(unittest.TestCase):
    def test_returns_singleton(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")

    def test_returns_rate_limiter_instance(self) -> None:
        pytest.skip("RateLimiter removed with legacy server")


if __name__ == "__main__":
    unittest.main()
