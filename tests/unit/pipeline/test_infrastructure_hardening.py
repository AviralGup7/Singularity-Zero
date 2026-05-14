"""Tests for infrastructure hardening: retry logic, cache integrity, storage validation."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from src.pipeline.cache_backend import PersistentCache
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
from src.pipeline.storage import (
    check_disk_space,
    preflight_storage_check,
    validate_storage,
)


class TestRetryPolicy:
    def test_default_policy(self) -> None:
        policy = RetryPolicy()
        assert policy.max_attempts == 1
        assert policy.initial_backoff_seconds == 0.0
        assert policy.backoff_multiplier == 2.0
        assert policy.max_backoff_seconds == 8.0
        assert policy.retry_on_timeout is True
        assert policy.retry_on_error is True
        assert policy.jitter_factor == 0.25

    def test_from_settings_uses_tool_overrides(self) -> None:
        tool_settings = {
            "retry_attempts": 3,
            "retry_backoff_seconds": 0.5,
            "retry_backoff_multiplier": 1.5,
            "retry_max_backoff_seconds": 4.0,
            "retry_on_timeout": False,
            "retry_on_error": False,
            "retry_jitter": 0.1,
        }
        policy = RetryPolicy.from_settings(global_settings=None, tool_settings=tool_settings)
        assert policy.max_attempts == 4
        assert policy.initial_backoff_seconds == 0.5
        assert policy.backoff_multiplier == 1.5
        assert policy.max_backoff_seconds == 4.0
        assert policy.retry_on_timeout is False
        assert policy.retry_on_error is False
        assert policy.jitter_factor == 0.1

    def test_from_settings_uses_global_defaults(self) -> None:
        global_settings = {"retry_attempts": 2, "retry_backoff_seconds": 2.0}
        policy = RetryPolicy.from_settings(global_settings=global_settings)
        assert policy.max_attempts == 3
        assert policy.initial_backoff_seconds == 2.0

    def test_from_settings_tool_overrides_global(self) -> None:
        global_settings = {"retry_attempts": 5}
        tool_settings = {"retry_attempts": 1}
        policy = RetryPolicy.from_settings(
            global_settings=global_settings, tool_settings=tool_settings
        )
        assert policy.max_attempts == 2

    def test_delay_for_attempt_first_attempt_is_zero(self) -> None:
        policy = RetryPolicy(initial_backoff_seconds=1.0)
        assert policy.delay_for_attempt(1) == 0.0

    def test_delay_for_attempt_exponential_backoff(self) -> None:
        policy = RetryPolicy(
            initial_backoff_seconds=1.0,
            backoff_multiplier=2.0,
            max_backoff_seconds=0.0,
            jitter_factor=0.0,
        )
        assert policy.delay_for_attempt(2, jitter=0.0) == 1.0
        assert policy.delay_for_attempt(3, jitter=0.0) == 2.0
        assert policy.delay_for_attempt(4, jitter=0.0) == 4.0

    def test_delay_for_attempt_respects_max_backoff(self) -> None:
        policy = RetryPolicy(
            initial_backoff_seconds=1.0,
            backoff_multiplier=2.0,
            max_backoff_seconds=3.0,
            jitter_factor=0.0,
        )
        delay = policy.delay_for_attempt(4, jitter=0.0)
        assert delay <= 3.0

    def test_delay_for_attempt_with_jitter(self) -> None:
        policy = RetryPolicy(
            initial_backoff_seconds=1.0,
            backoff_multiplier=1.0,
            max_backoff_seconds=0.0,
            jitter_factor=0.5,
        )
        delays = [policy.delay_for_attempt(2, jitter=0.5) for _ in range(20)]
        assert all(0.5 <= d <= 1.5 for d in delays)
        assert len(set(delays)) > 1

    def test_retry_ready(self) -> None:
        policy = RetryPolicy(max_attempts=3)
        assert retry_ready(policy, 0) is True
        assert retry_ready(policy, 1) is True
        assert retry_ready(policy, 2) is True
        assert retry_ready(policy, 3) is False

    def test_sleep_before_retry_returns_delay(self) -> None:
        policy = RetryPolicy(initial_backoff_seconds=0.01, jitter_factor=0.0)
        with patch("src.pipeline.retry.time.sleep"):
            delay = sleep_before_retry(policy, 1)
        assert delay > 0


class TestErrorClassification:
    def test_transient_connection_error(self) -> None:
        assert classify_error(ConnectionError("refused")) == "transient"

    def test_transient_timeout(self) -> None:
        assert classify_error(TimeoutError("timed out")) == "transient"

    def test_transient_os_error(self) -> None:
        assert classify_error(OSError("network unreachable")) == "transient"

    def test_transient_custom(self) -> None:
        assert classify_error(TransientError("retry me")) == "transient"

    def test_permanent_value_error(self) -> None:
        assert classify_error(ValueError("bad value")) == "permanent"

    def test_permanent_type_error(self) -> None:
        assert classify_error(TypeError("wrong type")) == "permanent"

    def test_permanent_custom(self) -> None:
        assert classify_error(PermanentError("auth failed")) == "permanent"

    def test_unknown_error(self) -> None:
        assert classify_error(RuntimeError("mystery")) == "unknown"

    def test_http_transient_status(self) -> None:
        class HttpError(Exception):
            status_code = 503

        assert classify_error(HttpError()) == "transient"

    def test_http_permanent_status(self) -> None:
        class HttpError(Exception):
            status_code = 404

        assert classify_error(HttpError()) == "permanent"


class TestIsRetryable:
    def test_transient_is_retryable(self) -> None:
        policy = RetryPolicy()
        assert is_retryable(ConnectionError(), policy) is True

    def test_permanent_is_not_retryable(self) -> None:
        policy = RetryPolicy()
        assert is_retryable(ValueError("bad"), policy) is False

    def test_timeout_not_retryable_when_disabled(self) -> None:
        policy = RetryPolicy(retry_on_timeout=False)
        assert is_retryable(TimeoutError(), policy) is False

    def test_timeout_retryable_when_enabled(self) -> None:
        policy = RetryPolicy(retry_on_timeout=True)
        assert is_retryable(TimeoutError(), policy) is True

    def test_unknown_retryable_when_retry_on_error(self) -> None:
        policy = RetryPolicy(retry_on_error=True)
        assert is_retryable(RuntimeError("mystery"), policy) is True

    def test_unknown_not_retryable_when_disabled(self) -> None:
        policy = RetryPolicy(retry_on_error=False)
        assert is_retryable(RuntimeError("mystery"), policy) is False


class TestRetryMetrics:
    def test_initial_state(self) -> None:
        m = RetryMetrics()
        assert m.total_attempts == 0
        assert m.total_retries == 0
        assert m.total_failures == 0
        assert m.total_successes == 0
        assert m.transient_errors == 0
        assert m.permanent_errors == 0
        assert m.total_backoff_seconds == 0.0

    def test_record_attempt(self) -> None:
        m = RetryMetrics()
        m.record_attempt()
        m.record_attempt()
        assert m.total_attempts == 2

    def test_record_retry(self) -> None:
        m = RetryMetrics()
        m.record_retry(1.5)
        m.record_retry(2.0)
        assert m.total_retries == 2
        assert m.total_backoff_seconds == 3.5

    def test_record_success(self) -> None:
        m = RetryMetrics()
        m.record_success()
        assert m.total_successes == 1

    def test_record_transient(self) -> None:
        m = RetryMetrics()
        m.record_transient()
        assert m.transient_errors == 1

    def test_record_permanent(self) -> None:
        m = RetryMetrics()
        m.record_permanent()
        assert m.permanent_errors == 1

    def test_retry_rate(self) -> None:
        m = RetryMetrics()
        m.record_attempt()
        m.record_attempt()
        m.record_attempt()
        m.record_retry()
        m.record_retry()
        assert m.retry_rate == pytest.approx(2 / 3)

    def test_retry_rate_zero_attempts(self) -> None:
        m = RetryMetrics()
        assert m.retry_rate == 0.0


class TestExecuteWithRetry:
    def test_succeeds_on_first_attempt(self) -> None:
        metrics = RetryMetrics()
        result = execute_with_retry(lambda: 42, RetryPolicy(), metrics)
        assert result == 42
        assert metrics.total_attempts == 1
        assert metrics.total_successes == 1

    def test_retries_transient_error_then_succeeds(self) -> None:
        metrics = RetryMetrics()
        call_count = [0]

        def flaky() -> int:
            call_count[0] += 1
            if call_count[0] < 3:
                raise ConnectionError("refused")
            return 99

        policy = RetryPolicy(max_attempts=5, initial_backoff_seconds=0.0, jitter_factor=0.0)
        with patch("src.pipeline.retry.time.sleep"):
            result = execute_with_retry(flaky, policy, metrics)
        assert result == 99
        assert call_count[0] == 3
        assert metrics.total_attempts == 3
        assert metrics.total_retries == 2
        assert metrics.transient_errors == 2
        assert metrics.total_successes == 1

    def test_raises_permanent_error_immediately(self) -> None:
        metrics = RetryMetrics()

        def always_bad() -> int:
            raise ValueError("bad")

        policy = RetryPolicy(max_attempts=5)
        with pytest.raises(ValueError):
            execute_with_retry(always_bad, policy, metrics)
        assert metrics.total_attempts == 1
        assert metrics.permanent_errors == 1
        assert metrics.total_failures == 1

    def test_raises_after_max_attempts(self) -> None:
        metrics = RetryMetrics()

        def always_transient() -> int:
            raise ConnectionError("refused")

        policy = RetryPolicy(max_attempts=3, initial_backoff_seconds=0.0, jitter_factor=0.0)
        with patch("src.pipeline.retry.time.sleep"):
            with pytest.raises(ConnectionError):
                execute_with_retry(always_transient, policy, metrics)
        assert metrics.total_attempts == 3
        assert metrics.total_failures == 1

    def test_timeout_not_retried_when_disabled(self) -> None:
        metrics = RetryMetrics()

        def always_timeout() -> int:
            raise TimeoutError("slow")

        policy = RetryPolicy(max_attempts=3, retry_on_timeout=False)
        with pytest.raises(TimeoutError):
            execute_with_retry(always_timeout, policy, metrics)
        assert metrics.total_attempts == 1

    def test_unknown_error_retried_when_enabled(self) -> None:
        metrics = RetryMetrics()
        call_count = [0]

        def flaky_unknown() -> int:
            call_count[0] += 1
            if call_count[0] < 2:
                raise RuntimeError("mystery")
            return 1

        policy = RetryPolicy(
            max_attempts=3, retry_on_error=True, initial_backoff_seconds=0.0, jitter_factor=0.0
        )
        with patch("src.pipeline.retry.time.sleep"):
            result = execute_with_retry(flaky_unknown, policy, metrics)
        assert result == 1
        assert call_count[0] == 2

    def test_unknown_error_not_retried_when_disabled(self) -> None:
        metrics = RetryMetrics()

        def always_unknown() -> int:
            raise RuntimeError("mystery")

        policy = RetryPolicy(max_attempts=3, retry_on_error=False)
        with pytest.raises(RuntimeError):
            execute_with_retry(always_unknown, policy, metrics)
        assert metrics.total_attempts == 1

    def test_metrics_passed_via_default(self) -> None:
        result = execute_with_retry(lambda: "ok", RetryPolicy())
        assert result == "ok"

    def test_jitter_prevents_thundering_herd(self) -> None:
        delays = []
        policy = RetryPolicy(
            max_attempts=10,
            initial_backoff_seconds=1.0,
            backoff_multiplier=1.0,
            max_backoff_seconds=0.0,
            jitter_factor=0.5,
        )
        for i in range(1, 10):
            d = policy.delay_for_attempt(i + 1)
            delays.append(d)
        assert len(set(delays)) > 1
        assert all(0.5 <= d <= 1.5 for d in delays)


class TestCacheIntegrity:
    @pytest.fixture
    def cache(self, tmp_path: Path) -> PersistentCache:
        db = str(tmp_path / "test_cache.db")
        return PersistentCache(db_path=db)

    def test_validate_integrity_healthy(self, cache: PersistentCache) -> None:
        cache.set("key1", "value1")
        result = cache.validate_integrity()
        assert result["healthy"] is True
        assert result["entry_count"] == 1
        assert result["db_size_bytes"] > 0
        assert result["issues"] == []

    def test_validate_integrity_missing_file(self, tmp_path: Path) -> None:
        PersistentCache(db_path=str(tmp_path / "nonexistent.db"))
        Path(tmp_path / "nonexistent.db").unlink(missing_ok=True)
        cache2 = PersistentCache.__new__(PersistentCache)
        cache2._db_path = str(tmp_path / "nonexistent.db")
        cache2._lock = __import__("threading").Lock()
        result = cache2.validate_integrity()
        assert result["healthy"] is False
        assert any("not exist" in issue for issue in result["issues"])

    def test_validate_integrity_corrupted(self, tmp_path: Path) -> None:
        db_path = tmp_path / "corrupt.db"
        db_path.write_bytes(b"this is not a valid sqlite database")
        cache = PersistentCache.__new__(PersistentCache)
        cache._db_path = str(db_path)
        cache._lock = __import__("threading").Lock()
        result = cache.validate_integrity()
        assert result["healthy"] is False
        assert len(result["issues"]) > 0

    def test_recover_from_corruption(self, tmp_path: Path) -> None:
        db_path = tmp_path / "corrupt.db"
        db_path.write_bytes(b"this is not a valid sqlite database")
        cache = PersistentCache.__new__(PersistentCache)
        cache._db_path = str(db_path)
        cache._lock = __import__("threading").Lock()
        recovered = cache.recover_from_corruption()
        assert recovered is True
        assert (tmp_path / "corrupt.db.corrupted.bak").exists()
        cache._init_db()
        cache.set("recovered", True)
        assert cache.get("recovered") is True

    def test_recover_from_corruption_no_file(self, tmp_path: Path) -> None:
        cache = PersistentCache.__new__(PersistentCache)
        cache._db_path = str(tmp_path / "missing.db")
        cache._lock = __import__("threading").Lock()
        recovered = cache.recover_from_corruption()
        assert recovered is True

    def test_get_disk_usage(self, cache: PersistentCache) -> None:
        cache.set("key", "value")
        usage = cache.get_disk_usage()
        assert usage["entry_count"] == 1
        assert usage["db_size_bytes"] > 0

    def test_cache_still_works_after_validation(self, cache: PersistentCache) -> None:
        cache.set("test", {"data": 123})
        cache.validate_integrity()
        assert cache.get("test") == {"data": 123}


class TestStorageValidation:
    def test_validate_storage_writable_directory(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "output"
        result = validate_storage(output_dir)
        assert result["writable"] is True
        assert result["errors"] == []
        assert result["free_bytes"] > 0
        assert result["free_gb"] > 0

    def test_validate_storage_existing_directory(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "existing"
        output_dir.mkdir()
        result = validate_storage(output_dir)
        assert result["writable"] is True

    def test_preflight_storage_check_passes(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "output"
        assert preflight_storage_check(output_dir) is True

    def test_check_disk_space_sufficient(self, tmp_path: Path) -> None:
        result = check_disk_space(tmp_path, min_bytes=100)
        assert result["sufficient"] is True
        assert result["free_bytes"] > 0

    def test_check_disk_space_insufficient(self, tmp_path: Path) -> None:
        huge = 10**18
        result = check_disk_space(tmp_path, min_bytes=huge)
        assert result["sufficient"] is False

    def test_validate_storage_readonly_dir(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "readonly"
        output_dir.mkdir()
        os.chmod(str(output_dir), 0o000)
        try:
            result = validate_storage(output_dir)
            if os.name != "nt":
                assert result["writable"] is False
                assert len(result["errors"]) > 0
        finally:
            os.chmod(str(output_dir), 0o755)

    def test_preflight_storage_check_fails_on_readonly(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "readonly"
        output_dir.mkdir()
        os.chmod(str(output_dir), 0o000)
        try:
            if os.name != "nt":
                assert preflight_storage_check(output_dir) is False
        finally:
            os.chmod(str(output_dir), 0o755)

    def test_validate_storage_warns_on_low_space(self, tmp_path: Path) -> None:
        huge = 10**18
        validate_storage(tmp_path)
        result2 = check_disk_space(tmp_path, min_bytes=huge)
        assert result2["sufficient"] is False
