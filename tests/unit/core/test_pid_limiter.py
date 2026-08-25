"""Unit tests for the PID Rate Limiter (Proactive Concurrency Control)."""

from __future__ import annotations

from src.core.pid_limiter import PIDRateLimiter


def test_pid_limiter_initialization():
    """Verify that PID rate limiter initializes with default values."""
    limiter = PIDRateLimiter(target_latency_seconds=0.200)
    assert limiter.target_latency == 0.200
    assert limiter.kp == 0.5
    assert limiter.ki == 0.1
    assert limiter.kd == 0.05
    assert limiter.current_delay == 0.0


def test_pid_limiter_under_latency_increases_delay():
    """Verify that high latency increases delay pacing."""
    limiter = PIDRateLimiter(target_latency_seconds=0.200, kp=1.0, ki=0.0, kd=0.0)
    # Observed latency is 0.500 (300ms above target)
    new_delay = limiter.update(observed_latency_seconds=0.500, is_blocked=False)
    # Output should increase by kp * error = 1.0 * 0.3 = 0.3
    assert new_delay == 0.3
    assert limiter.current_delay == 0.3


def test_pid_limiter_under_target_latency_reduces_delay():
    """Verify that low latency reduces delay pacing to minimum."""
    limiter = PIDRateLimiter(target_latency_seconds=0.200, kp=1.0, ki=0.0, kd=0.0)
    limiter.current_delay = 0.5
    # Observed latency is 0.100 (100ms below target)
    new_delay = limiter.update(observed_latency_seconds=0.100, is_blocked=False)
    # Output is current_delay + (1.0 * -0.1) = 0.5 - 0.1 = 0.4
    assert new_delay == 0.4


def test_pid_limiter_immediate_penalty_on_block():
    """Verify that block signals apply severe immediate penalty."""
    limiter = PIDRateLimiter(target_latency_seconds=0.200, max_delay_seconds=5.0)
    assert limiter.current_delay == 0.0

    # Simulate WAF/blocking signal
    new_delay = limiter.update(observed_latency_seconds=0.0, is_blocked=True)

    # Output should jump immediately by penalty offset (1.5s)
    assert new_delay == 1.5
    assert limiter.integral == 0.0
    assert limiter.last_error == 0.0
