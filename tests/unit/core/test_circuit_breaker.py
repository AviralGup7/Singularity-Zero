import pytest

from src.core.security.circuit_breaker import CircuitBreaker, CircuitBreakerOpenException


def test_circuit_breaker_half_open_failure_reopens(monkeypatch):
    now = 100.0
    monkeypatch.setattr("src.core.security.circuit_breaker.time.monotonic", lambda: now)
    breaker = CircuitBreaker("svc", failure_threshold=2, recovery_timeout=5.0)

    def fail():
        raise RuntimeError("down")

    with pytest.raises(RuntimeError):
        breaker.call(fail)
    with pytest.raises(RuntimeError):
        breaker.call(fail)
    assert breaker.state == "OPEN"

    now = 105.0
    with pytest.raises(RuntimeError):
        breaker.call(fail)
    assert breaker.state == "OPEN"

    with pytest.raises(CircuitBreakerOpenException):
        breaker.call(lambda: "blocked")


def test_circuit_breaker_uses_fallback_while_open(monkeypatch):
    now = 100.0
    monkeypatch.setattr("src.core.security.circuit_breaker.time.monotonic", lambda: now)
    breaker = CircuitBreaker(
        "svc",
        failure_threshold=1,
        recovery_timeout=10.0,
        fallback_fn=lambda: "fallback",
    )

    def fail():
        raise RuntimeError("down")

    assert breaker.call(fail) == "fallback"
    assert breaker.state == "OPEN"
    assert breaker.call(lambda: "not-called") == "fallback"
