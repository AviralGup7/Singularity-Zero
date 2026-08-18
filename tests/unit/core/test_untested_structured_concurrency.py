"""Coverage for previously untested structured-concurrency sync helpers."""

from __future__ import annotations

import pytest

from src.core.concurrency.structured import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    RateLimiter,
    RetryPolicy,
    SemaphorePool,
)
from src.core.utils.scheduler import RequestScheduler


@pytest.mark.unit
def test_retry_policy_delay_is_exponential_with_optional_jitter() -> None:
    exact = RetryPolicy(base_delay=1.0, max_delay=60.0, exponential_base=2.0, jitter=0.0)
    assert exact.get_delay(0) == 1.0
    assert exact.get_delay(1) == 2.0
    assert exact.get_delay(3) == 8.0
    capped = RetryPolicy(base_delay=10.0, max_delay=15.0, exponential_base=2.0, jitter=0.0)
    assert capped.get_delay(4) == 15.0
    noisy = RetryPolicy(base_delay=2.0, max_delay=60.0, exponential_base=2.0, jitter=0.1)
    delay = noisy.get_delay(1)
    assert 3.6 <= delay <= 4.4


@pytest.mark.unit
def test_circuit_breaker_starts_closed_and_exposes_stats() -> None:
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
    assert breaker.state == "closed"
    stats = breaker.stats()
    assert stats["state"] == "closed"
    assert stats["failure_count"] == 0
    assert issubclass(CircuitBreakerOpenError, Exception)


@pytest.mark.unit
def test_semaphore_pool_stats_before_acquire() -> None:
    pool = SemaphorePool(max_concurrent=4)
    stats = pool.stats()
    assert stats["max_concurrent"] == 4
    assert stats["active"] == 0
    assert stats["available"] == 4
    assert stats["total_acquired"] == 0
    assert stats["total_released"] == 0
    assert pool.available == 4


@pytest.mark.unit
def test_rate_limiter_starts_with_burst_tokens() -> None:
    limiter = RateLimiter(rate_per_second=5.0, burst=3)
    stats = limiter.stats()
    assert stats["rate_per_second"] == 5.0
    assert stats["burst"] == 3
    assert stats["available_tokens"] == 3.0


@pytest.mark.unit
def test_request_scheduler_observe_is_noop_without_adaptive() -> None:
    sched = RequestScheduler(rate_per_second=2.0, capacity=2.0, adaptive_mode=False)
    before = sched.current_rate_per_second
    sched.observe(successful=False, latency_seconds=9.0, status_code=429)
    assert sched.current_rate_per_second == before


@pytest.mark.unit
def test_request_scheduler_adaptive_backoff_and_ramp() -> None:
    sched = RequestScheduler(
        rate_per_second=4.0,
        capacity=4.0,
        adaptive_mode=True,
        min_rate_per_second=0.5,
        max_rate_per_second=10.0,
        success_window=2,
        increase_step=1.0,
        error_backoff_factor=0.5,
    )
    sched.observe(successful=False, latency_seconds=0.1, status_code=500)
    assert sched.current_rate_per_second == pytest.approx(2.0)
    sched.observe(successful=False, latency_seconds=0.1, status_code=429)
    assert sched.current_rate_per_second == pytest.approx(0.5)
    sched.observe(successful=True, latency_seconds=0.1)
    sched.observe(successful=True, latency_seconds=0.1)
    assert sched.current_rate_per_second == pytest.approx(1.5)


@pytest.mark.unit
def test_request_scheduler_retry_after_resets_healthy_streak() -> None:
    sched = RequestScheduler(
        rate_per_second=8.0,
        capacity=8.0,
        adaptive_mode=True,
        min_rate_per_second=1.0,
        success_window=2,
    )
    sched.observe(successful=True, latency_seconds=0.1)
    sched.observe(successful=True, latency_seconds=0.1, retry_after_seconds=1.0)
    assert sched.current_rate_per_second < 8.0
    assert sched._healthy_streak == 0
