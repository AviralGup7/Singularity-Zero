"""Unit tests for pipeline_platform.retry module."""

import unittest
from unittest.mock import MagicMock, patch

import pytest

from src.pipeline.retry import (
    PermanentError,
    RetryMetrics,
    RetryPolicy,
    TransientError,
    classify_error,
    execute_with_retry,
    is_retryable,
    retry_ready,
    sleep_before_retry,
)


@pytest.mark.unit
class TestDelayForAttempt(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = RetryPolicy(
            max_attempts=5,
            initial_backoff_seconds=1.0,
            backoff_multiplier=2.0,
            max_backoff_seconds=8.0,
            jitter_factor=0.0,
        )

    def test_attempt_1_returns_zero(self) -> None:
        self.assertEqual(self.policy.delay_for_attempt(1), 0.0)

    def test_attempt_0_returns_zero(self) -> None:
        self.assertEqual(self.policy.delay_for_attempt(0), 0.0)

    def test_attempt_2_returns_initial_backoff(self) -> None:
        self.assertAlmostEqual(self.policy.delay_for_attempt(2, jitter=0.0), 1.0)

    def test_attempt_3_returns_doubled_backoff(self) -> None:
        self.assertAlmostEqual(self.policy.delay_for_attempt(3, jitter=0.0), 2.0)

    def test_attempt_4_returns_quadrupled_backoff(self) -> None:
        self.assertAlmostEqual(self.policy.delay_for_attempt(4, jitter=0.0), 4.0)

    def test_attempt_5_capped_at_max_backoff(self) -> None:
        delay = self.policy.delay_for_attempt(5, jitter=0.0)
        self.assertAlmostEqual(delay, 8.0)

    def test_attempt_6_still_capped_at_max_backoff(self) -> None:
        delay = self.policy.delay_for_attempt(6, jitter=0.0)
        self.assertAlmostEqual(delay, 8.0)

    def test_zero_initial_backoff_returns_zero(self) -> None:
        policy = RetryPolicy(initial_backoff_seconds=0.0)
        self.assertEqual(policy.delay_for_attempt(2), 0.0)

    def test_negative_initial_backoff_returns_zero(self) -> None:
        policy = RetryPolicy(initial_backoff_seconds=-1.0)
        self.assertEqual(policy.delay_for_attempt(2), 0.0)


@pytest.mark.unit
class TestDelayForAttemptJitter(unittest.TestCase):
    def test_jitter_applied(self) -> None:
        policy = RetryPolicy(
            initial_backoff_seconds=1.0,
            backoff_multiplier=1.0,
            max_backoff_seconds=0.0,
            jitter_factor=0.0,
        )
        delay_no_jitter = policy.delay_for_attempt(2, jitter=0.0)
        self.assertEqual(delay_no_jitter, 1.0)

    def test_jitter_reduces_delay(self) -> None:
        policy = RetryPolicy(
            initial_backoff_seconds=10.0,
            backoff_multiplier=1.0,
            max_backoff_seconds=0.0,
            jitter_factor=0.0,
        )
        results = [policy.delay_for_attempt(2, jitter=0.5) for _ in range(20)]
        self.assertTrue(any(r < 10.0 for r in results))
        self.assertTrue(any(r > 10.0 for r in results))

    def test_jitter_does_not_go_below_zero(self) -> None:
        policy = RetryPolicy(
            initial_backoff_seconds=1.0,
            backoff_multiplier=1.0,
            max_backoff_seconds=0.0,
            jitter_factor=0.0,
        )
        results = [policy.delay_for_attempt(2, jitter=0.99) for _ in range(50)]
        self.assertTrue(all(r >= 0.0 for r in results))

    def test_zero_jitter_returns_exact_delay(self) -> None:
        policy = RetryPolicy(
            initial_backoff_seconds=2.0,
            backoff_multiplier=2.0,
            max_backoff_seconds=0.0,
            jitter_factor=0.0,
        )
        self.assertEqual(policy.delay_for_attempt(3, jitter=0.0), 4.0)


@pytest.mark.unit
class TestRetryPolicyCreation(unittest.TestCase):
    def test_default_values(self) -> None:
        policy = RetryPolicy()
        self.assertEqual(policy.max_attempts, 1)
        self.assertEqual(policy.initial_backoff_seconds, 0.0)
        self.assertEqual(policy.backoff_multiplier, 2.0)
        self.assertEqual(policy.max_backoff_seconds, 8.0)
        self.assertTrue(policy.retry_on_timeout)
        self.assertTrue(policy.retry_on_error)
        self.assertEqual(policy.jitter_factor, 0.25)

    def test_custom_values(self) -> None:
        policy = RetryPolicy(
            max_attempts=5,
            initial_backoff_seconds=2.0,
            backoff_multiplier=3.0,
            max_backoff_seconds=30.0,
            retry_on_timeout=False,
            retry_on_error=False,
            jitter_factor=0.5,
        )
        self.assertEqual(policy.max_attempts, 5)
        self.assertEqual(policy.initial_backoff_seconds, 2.0)
        self.assertEqual(policy.backoff_multiplier, 3.0)
        self.assertEqual(policy.max_backoff_seconds, 30.0)
        self.assertFalse(policy.retry_on_timeout)
        self.assertFalse(policy.retry_on_error)
        self.assertEqual(policy.jitter_factor, 0.5)


@pytest.mark.unit
class TestRetryPolicyFromSettings(unittest.TestCase):
    def test_defaults_from_retry_defaults(self) -> None:
        policy = RetryPolicy.from_settings()
        self.assertEqual(policy.max_attempts, 1)
        self.assertEqual(policy.initial_backoff_seconds, 2.0)
        self.assertEqual(policy.backoff_multiplier, 1.0)
        self.assertEqual(policy.max_backoff_seconds, 2.0)
        self.assertTrue(policy.retry_on_timeout)
        self.assertTrue(policy.retry_on_error)

    def test_tool_settings_override_global(self) -> None:
        global_settings = {"retry_attempts": 2, "retry_backoff_seconds": 1.0}
        tool_settings = {"retry_attempts": 5, "retry_backoff_seconds": 3.0}
        policy = RetryPolicy.from_settings(global_settings, tool_settings)
        self.assertEqual(policy.max_attempts, 6)
        self.assertEqual(policy.initial_backoff_seconds, 3.0)

    def test_global_settings_used_when_no_tool_settings(self) -> None:
        global_settings = {"retry_attempts": 3, "retry_backoff_seconds": 2.0}
        policy = RetryPolicy.from_settings(global_settings, None)
        self.assertEqual(policy.max_attempts, 4)
        self.assertEqual(policy.initial_backoff_seconds, 2.0)

    def test_empty_settings_uses_defaults(self) -> None:
        policy = RetryPolicy.from_settings({}, {})
        self.assertEqual(policy.max_attempts, 1)
        self.assertEqual(policy.initial_backoff_seconds, 2.0)

    def test_invalid_retry_attempts_uses_default(self) -> None:
        tool_settings = {"retry_attempts": "not_a_number"}
        policy = RetryPolicy.from_settings(None, tool_settings)
        self.assertEqual(policy.max_attempts, 1)

    def test_negative_retry_attempts_clamped_to_zero(self) -> None:
        tool_settings = {"retry_attempts": -5}
        policy = RetryPolicy.from_settings(None, tool_settings)
        self.assertEqual(policy.max_attempts, 1)

    def test_jitter_from_settings(self) -> None:
        tool_settings = {"retry_jitter": 0.5}
        policy = RetryPolicy.from_settings(None, tool_settings)
        self.assertEqual(policy.jitter_factor, 0.5)

    def test_invalid_jitter_uses_default(self) -> None:
        tool_settings = {"retry_jitter": "invalid"}
        policy = RetryPolicy.from_settings(None, tool_settings)
        self.assertEqual(policy.jitter_factor, 0.25)

    def test_backoff_multiplier_minimum_1(self) -> None:
        tool_settings = {"retry_backoff_multiplier": 0.5}
        policy = RetryPolicy.from_settings(None, tool_settings)
        self.assertEqual(policy.backoff_multiplier, 1.0)

    def test_max_backoff_minimum_0(self) -> None:
        tool_settings = {"retry_max_backoff_seconds": -1.0}
        policy = RetryPolicy.from_settings(None, tool_settings)
        self.assertEqual(policy.max_backoff_seconds, 0.0)


@pytest.mark.unit
class TestClassifyError(unittest.TestCase):
    def test_timeout_is_transient(self) -> None:
        self.assertEqual(classify_error(TimeoutError("timeout")), "transient")

    def test_connection_error_is_transient(self) -> None:
        self.assertEqual(classify_error(ConnectionError("conn")), "transient")

    def test_connection_refused_is_transient(self) -> None:
        self.assertEqual(classify_error(ConnectionRefusedError("refused")), "transient")

    def test_connection_reset_is_transient(self) -> None:
        self.assertEqual(classify_error(ConnectionResetError("reset")), "transient")

    def test_oserror_is_transient(self) -> None:
        self.assertEqual(classify_error(OSError("os error")), "transient")

    def test_transient_error_is_transient(self) -> None:
        self.assertEqual(classify_error(TransientError("transient")), "transient")

    def test_permanent_error_is_permanent(self) -> None:
        self.assertEqual(classify_error(PermanentError("permanent")), "permanent")

    def test_value_error_is_permanent(self) -> None:
        self.assertEqual(classify_error(ValueError("bad value")), "permanent")

    def test_type_error_is_permanent(self) -> None:
        self.assertEqual(classify_error(TypeError("bad type")), "permanent")

    def test_key_error_is_permanent(self) -> None:
        self.assertEqual(classify_error(KeyError("missing")), "permanent")

    def test_attribute_error_is_permanent(self) -> None:
        self.assertEqual(classify_error(AttributeError("no attr")), "permanent")

    def test_http_500_is_transient(self) -> None:
        exc = Exception("server error")
        exc.status_code = 500
        self.assertEqual(classify_error(exc), "transient")

    def test_http_503_is_transient(self) -> None:
        exc = Exception("service unavailable")
        exc.status_code = 503
        self.assertEqual(classify_error(exc), "transient")

    def test_http_429_is_transient(self) -> None:
        exc = Exception("rate limited")
        exc.status_code = 429
        self.assertEqual(classify_error(exc), "transient")

    def test_http_404_is_permanent(self) -> None:
        exc = Exception("not found")
        exc.status_code = 404
        self.assertEqual(classify_error(exc), "permanent")

    def test_http_401_is_permanent(self) -> None:
        exc = Exception("unauthorized")
        exc.status_code = 401
        self.assertEqual(classify_error(exc), "permanent")

    def test_http_403_is_permanent(self) -> None:
        exc = Exception("forbidden")
        exc.status_code = 403
        self.assertEqual(classify_error(exc), "permanent")

    def test_unknown_exception_is_unknown(self) -> None:
        self.assertEqual(classify_error(RuntimeError("unknown")), "unknown")

    def test_http_status_via_response_attr(self) -> None:
        class FakeResponse:
            status_code = 502

        exc = Exception("bad gateway")
        exc.response = FakeResponse()
        self.assertEqual(classify_error(exc), "transient")


@pytest.mark.unit
class TestIsRetryable(unittest.TestCase):
    def test_transient_is_retryable(self) -> None:
        policy = RetryPolicy()
        self.assertTrue(is_retryable(TimeoutError("timeout"), policy))

    def test_permanent_is_not_retryable(self) -> None:
        policy = RetryPolicy()
        self.assertFalse(is_retryable(ValueError("bad"), policy))

    def test_timeout_not_retryable_when_disabled(self) -> None:
        policy = RetryPolicy(retry_on_timeout=False)
        self.assertFalse(is_retryable(TimeoutError("timeout"), policy))

    def test_unknown_retryable_when_retry_on_error(self) -> None:
        policy = RetryPolicy(retry_on_error=True)
        self.assertTrue(is_retryable(RuntimeError("unknown"), policy))

    def test_unknown_not_retryable_when_retry_on_error_false(self) -> None:
        policy = RetryPolicy(retry_on_error=False)
        self.assertFalse(is_retryable(RuntimeError("unknown"), policy))


@pytest.mark.unit
class TestRetryReady(unittest.TestCase):
    def test_attempt_less_than_max(self) -> None:
        policy = RetryPolicy(max_attempts=3)
        self.assertTrue(retry_ready(policy, 1))
        self.assertTrue(retry_ready(policy, 2))

    def test_attempt_equals_max(self) -> None:
        policy = RetryPolicy(max_attempts=3)
        self.assertFalse(retry_ready(policy, 3))

    def test_attempt_greater_than_max(self) -> None:
        policy = RetryPolicy(max_attempts=3)
        self.assertFalse(retry_ready(policy, 5))


@pytest.mark.unit
class TestSleepBeforeRetry(unittest.TestCase):
    @patch("src.pipeline.retry.time.sleep")
    def test_sleep_called_with_delay(self, mock_sleep: MagicMock) -> None:
        policy = RetryPolicy(
            max_attempts=3,
            initial_backoff_seconds=1.0,
            backoff_multiplier=1.0,
            max_backoff_seconds=0.0,
            jitter_factor=0.0,
        )
        delay = sleep_before_retry(policy, 1)
        mock_sleep.assert_called_once()
        self.assertEqual(delay, 1.0)

    @patch("src.pipeline.retry.time.sleep")
    def test_no_sleep_for_attempt_0(self, mock_sleep: MagicMock) -> None:
        policy = RetryPolicy(
            max_attempts=3,
            initial_backoff_seconds=1.0,
            backoff_multiplier=1.0,
            max_backoff_seconds=0.0,
            jitter_factor=0.0,
        )
        delay = sleep_before_retry(policy, 0)
        mock_sleep.assert_not_called()
        self.assertEqual(delay, 0.0)


@pytest.mark.unit
class TestRetryMetrics(unittest.TestCase):
    def test_initial_values(self) -> None:
        m = RetryMetrics()
        self.assertEqual(m.total_attempts, 0)
        self.assertEqual(m.total_retries, 0)
        self.assertEqual(m.total_failures, 0)
        self.assertEqual(m.total_successes, 0)
        self.assertEqual(m.transient_errors, 0)
        self.assertEqual(m.permanent_errors, 0)
        self.assertEqual(m.total_backoff_seconds, 0.0)

    def test_record_attempt(self) -> None:
        m = RetryMetrics()
        m.record_attempt()
        m.record_attempt()
        self.assertEqual(m.total_attempts, 2)

    def test_record_retry(self) -> None:
        m = RetryMetrics()
        m.record_retry(backoff=1.5)
        m.record_retry(backoff=2.5)
        self.assertEqual(m.total_retries, 2)
        self.assertEqual(m.total_backoff_seconds, 4.0)

    def test_record_success(self) -> None:
        m = RetryMetrics()
        m.record_success()
        self.assertEqual(m.total_successes, 1)

    def test_record_transient(self) -> None:
        m = RetryMetrics()
        m.record_transient()
        self.assertEqual(m.transient_errors, 1)

    def test_record_permanent(self) -> None:
        m = RetryMetrics()
        m.record_permanent()
        self.assertEqual(m.permanent_errors, 1)

    def test_record_failure(self) -> None:
        m = RetryMetrics()
        m.record_failure()
        self.assertEqual(m.total_failures, 1)

    def test_retry_rate_zero_attempts(self) -> None:
        m = RetryMetrics()
        self.assertEqual(m.retry_rate, 0.0)

    def test_retry_rate_calculation(self) -> None:
        m = RetryMetrics()
        m.record_attempt()
        m.record_attempt()
        m.record_attempt()
        m.record_attempt()
        m.record_retry()
        m.record_retry()
        self.assertEqual(m.retry_rate, 0.5)


@pytest.mark.unit
class TestExecuteWithRetry(unittest.TestCase):
    def test_success_on_first_attempt(self) -> None:
        func = MagicMock(return_value="ok")
        policy = RetryPolicy(max_attempts=3)
        result = execute_with_retry(func, policy)
        self.assertEqual(result, "ok")
        func.assert_called_once()

    def test_success_after_retries(self) -> None:
        func = MagicMock(side_effect=[TransientError("fail"), TransientError("fail"), "ok"])
        policy = RetryPolicy(
            max_attempts=3,
            initial_backoff_seconds=0.0,
            backoff_multiplier=1.0,
            max_backoff_seconds=0.0,
            jitter_factor=0.0,
        )
        result = execute_with_retry(func, policy)
        self.assertEqual(result, "ok")
        self.assertEqual(func.call_count, 3)

    def test_permanent_error_raises_immediately(self) -> None:
        func = MagicMock(side_effect=ValueError("permanent"))
        policy = RetryPolicy(max_attempts=3)
        with self.assertRaises(ValueError):
            execute_with_retry(func, policy)
        func.assert_called_once()

    def test_exhausted_retries_raises(self) -> None:
        func = MagicMock(side_effect=TransientError("fail"))
        policy = RetryPolicy(
            max_attempts=2,
            initial_backoff_seconds=0.0,
            backoff_multiplier=1.0,
            max_backoff_seconds=0.0,
            jitter_factor=0.0,
        )
        with self.assertRaises(TransientError):
            execute_with_retry(func, policy)
        self.assertEqual(func.call_count, 2)

    def test_metrics_updated_on_success(self) -> None:
        func = MagicMock(return_value="ok")
        policy = RetryPolicy(max_attempts=3)
        metrics = RetryMetrics()
        execute_with_retry(func, policy, metrics)
        self.assertEqual(metrics.total_attempts, 1)
        self.assertEqual(metrics.total_successes, 1)

    def test_metrics_updated_on_failure(self) -> None:
        func = MagicMock(side_effect=TransientError("fail"))
        policy = RetryPolicy(
            max_attempts=2,
            initial_backoff_seconds=0.0,
            backoff_multiplier=1.0,
            max_backoff_seconds=0.0,
            jitter_factor=0.0,
        )
        metrics = RetryMetrics()
        with self.assertRaises(TransientError):
            execute_with_retry(func, policy, metrics)
        self.assertEqual(metrics.total_attempts, 2)
        self.assertEqual(metrics.total_failures, 1)
        self.assertEqual(metrics.transient_errors, 2)

    def test_metrics_updated_on_permanent_error(self) -> None:
        func = MagicMock(side_effect=ValueError("bad"))
        policy = RetryPolicy(max_attempts=3)
        metrics = RetryMetrics()
        with self.assertRaises(ValueError):
            execute_with_retry(func, policy, metrics)
        self.assertEqual(metrics.total_attempts, 1)
        self.assertEqual(metrics.permanent_errors, 1)
        self.assertEqual(metrics.total_failures, 1)

    def test_args_and_kwargs_passed_to_func(self) -> None:
        func = MagicMock(return_value="ok")
        policy = RetryPolicy(max_attempts=1)
        execute_with_retry(func, policy, None, "arg1", "arg2", kw="value")
        func.assert_called_once_with("arg1", "arg2", kw="value")


if __name__ == "__main__":
    unittest.main()
