"""Coverage for src.core.security.circuit_breaker."""

from __future__ import annotations

import pytest

from src.core.security.circuit_breaker import CircuitBreaker, CircuitBreakerOpenException


@pytest.mark.unit
def test_closed_success_resets_failure_count() -> None:
    breaker = CircuitBreaker("svc", failure_threshold=2, recovery_timeout=0.05)
    assert breaker.call(lambda: 7) == 7
    assert breaker.state == "CLOSED"
    assert breaker.failure_count == 0


@pytest.mark.unit
def test_threshold_trips_open_and_fail_fast() -> None:
    breaker = CircuitBreaker("svc", failure_threshold=2, recovery_timeout=60.0)

    def boom() -> None:
        raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        breaker.call(boom)
    with pytest.raises(RuntimeError):
        breaker.call(boom)
    assert breaker.state == "OPEN"
    with pytest.raises(CircuitBreakerOpenException, match="OPEN"):
        breaker.call(lambda: "never")


@pytest.mark.unit
def test_fallback_used_when_open() -> None:
    breaker = CircuitBreaker(
        "svc",
        failure_threshold=1,
        recovery_timeout=60.0,
        fallback_fn=lambda: "degraded",
    )
    first = breaker.call(lambda: (_ for _ in ()).throw(RuntimeError("x")))
    assert first == "degraded"
    assert breaker.state == "OPEN"
    assert breaker.call(lambda: "live") == "degraded"


@pytest.mark.unit
def test_single_threshold_opens_on_first_failure() -> None:
    breaker = CircuitBreaker("svc", failure_threshold=1, recovery_timeout=60.0)
    with pytest.raises(ValueError):
        breaker.call(lambda: (_ for _ in ()).throw(ValueError("nope")))
    assert breaker.state == "OPEN"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_call_async_success_and_failure() -> None:
    breaker = CircuitBreaker("async", failure_threshold=2, recovery_timeout=0.05)

    async def ok() -> str:
        return "yes"

    assert await breaker.call_async(ok) == "yes"

    async def bad() -> str:
        raise TimeoutError("slow")

    with pytest.raises(TimeoutError):
        await breaker.call_async(bad)
    assert breaker.failure_count == 1
