from __future__ import annotations

from src.resilience import ToolCircuitBreaker, override_backoff, parse_retry_after
from src.resilience.circuit_breaker import CircuitState


def test_parse_seconds_header() -> None:
    assert parse_retry_after_from_headers({"Retry-After": "12"}) == 12.0


def test_parse_stderr_text() -> None:
    assert parse_retry_after("rate limited Retry-After: 7") == 7.0


def test_exception_headers_win_over_computed_backoff() -> None:
    exc = Exception("429")
    exc.headers = {"Retry-After": "4"}  # type: ignore[attr-defined]
    assert override_backoff(0.25, exc) == 4.0


def test_no_retry_after_keeps_computed() -> None:
    assert override_backoff(1.5, Exception("boom")) == 1.5


def test_breaker_snapshot_roundtrip() -> None:
    breaker = ToolCircuitBreaker(failure_threshold=2, recovery_timeout=30.0)
    breaker.record_failure("nuclei", "timeout")
    breaker.record_failure("nuclei", "timeout")
    assert breaker.get_state("nuclei") is CircuitState.OPEN
    payload = breaker.snapshot()
    clone = ToolCircuitBreaker()
    clone.restore(payload)
    assert clone.get_state("nuclei") is CircuitState.OPEN
    assert clone.failure_threshold == 2


def test_execute_with_retry_honors_retry_after(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.pipeline.retry import RetryPolicy, TransientError, execute_with_retry

    sleeps: list[float] = []
    monkeypatch.setattr("src.pipeline.retry.policy.time.sleep", lambda seconds: sleeps.append(seconds))

    class RateLimited(TransientError):
        headers = {"Retry-After": "3"}

    calls = {"n": 0}

    def flaky() -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RateLimited("slow down")
        return "ok"

    policy = RetryPolicy(
        max_attempts=2,
        initial_backoff_seconds=0.1,
        backoff_multiplier=1.0,
        max_backoff_seconds=8.0,
        jitter_factor=0.0,
    )
    assert execute_with_retry(flaky, policy) == "ok"
    assert sleeps == [3.0]


def parse_retry_after_from_headers(headers: dict[str, str]) -> float | None:
    class Box:
        pass

    box = Box()
    box.headers = headers  # type: ignore[attr-defined]
    return parse_retry_after(box)
