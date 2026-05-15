import unittest
from unittest.mock import patch

from src.analysis.passive.runtime import (
    FetchResponseResult,
    RequestRetryPolicy,
    RequestScheduler,
    ResponseCache,
)


class PassiveAnalysisRuntimeTests(unittest.TestCase):
    def test_adaptive_scheduler_increases_rate_after_healthy_streak(self) -> None:
        scheduler = RequestScheduler(
            2.0,
            1.5,
            adaptive_mode=True,
            max_rate_per_second=4.0,
            increase_step=0.5,
            success_window=2,
        )

        scheduler.observe(successful=True, latency_seconds=0.2, status_code=200)
        scheduler.observe(successful=True, latency_seconds=0.2, status_code=200)

        self.assertEqual(scheduler.current_rate_per_second, 2.5)
        self.assertGreaterEqual(scheduler.current_capacity, 1.75)

    def test_adaptive_scheduler_backs_off_on_latency_or_error(self) -> None:
        scheduler = RequestScheduler(
            4.0,
            3.0,
            adaptive_mode=True,
            latency_threshold_seconds=1.0,
            error_backoff_factor=0.5,
            latency_backoff_factor=0.75,
        )

        scheduler.observe(successful=True, latency_seconds=1.6, status_code=200)
        self.assertEqual(scheduler.current_rate_per_second, 3.0)

        scheduler.observe(successful=False, latency_seconds=0.3, status_code=None)
        self.assertEqual(scheduler.current_rate_per_second, 1.5)
        self.assertLessEqual(scheduler.current_capacity, 2.25)

    def test_response_cache_retries_transient_failures_in_auto_max_speed_mode(self) -> None:
        scheduler = RequestScheduler(2.0, 2.0, adaptive_mode=True)
        cache = ResponseCache(
            timeout_seconds=8,
            max_bytes=1024,
            max_workers=1,
            scheduler=scheduler,
            persistent_cache_path=None,
            cache_ttl_hours=24,
            request_retry_policy=RequestRetryPolicy(max_attempts=2, initial_backoff_seconds=0.5),
        )
        attempts = [
            FetchResponseResult(
                record=None, latency_seconds=0.2, status_code=None, successful=False, retryable=True
            ),
            FetchResponseResult(
                record={"url": "https://example.com", "status_code": 200},
                latency_seconds=0.2,
                status_code=200,
                successful=True,
                retryable=False,
            ),
        ]

        with (
            patch.object(scheduler, "acquire") as acquire_mock,
            patch.object(scheduler, "observe") as observe_mock,
            patch(
                "src.analysis.passive.runtime._fetch_response_once", side_effect=attempts
            ) as fetch_mock,
            patch("src.analysis.passive.runtime.time.sleep") as sleep_mock,
        ):
            record = cache.request("https://example.com/api", method="POST")

        self.assertEqual(record, {"url": "https://example.com", "status_code": 200})
        self.assertEqual(fetch_mock.call_count, 2)
        self.assertEqual(acquire_mock.call_count, 2)
        self.assertEqual(observe_mock.call_count, 2)
        sleep_mock.assert_called_once()
        self.assertAlmostEqual(sleep_mock.call_args[0][0], 0.5, delta=0.25)

    def test_response_cache_keeps_single_attempt_when_auto_mode_is_disabled(self) -> None:
        scheduler = RequestScheduler(2.0, 2.0)
        cache = ResponseCache(
            timeout_seconds=8,
            max_bytes=1024,
            max_workers=1,
            scheduler=scheduler,
            persistent_cache_path=None,
            cache_ttl_hours=24,
            request_retry_policy=RequestRetryPolicy(max_attempts=1),
        )

        with (
            patch.object(scheduler, "acquire") as acquire_mock,
            patch.object(scheduler, "observe") as observe_mock,
            patch(
                "src.analysis.passive.runtime._fetch_response_once",
                return_value=FetchResponseResult(
                    record=None,
                    latency_seconds=0.2,
                    status_code=None,
                    successful=False,
                    retryable=True,
                ),
            ) as fetch_mock,
            patch("src.analysis.passive.runtime.time.sleep") as sleep_mock,
        ):
            record = cache.request("https://example.com/api", method="POST")

        self.assertIsNone(record)
        self.assertEqual(fetch_mock.call_count, 1)
        self.assertEqual(acquire_mock.call_count, 1)
        self.assertEqual(observe_mock.call_count, 1)
        sleep_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
