"""Retry / backoff policy for the UI client and gateway rate limiter."""

from __future__ import annotations

from dataclasses import dataclass

from src.integration.errors import ErrorCode


@dataclass(frozen=True, slots=True)
class RetryAdvice:
    retry: bool
    after_seconds: float
    reason: str


_RETRYABLE = frozenset({ErrorCode.RATE_LIMITED, ErrorCode.UNAVAILABLE, ErrorCode.INTERNAL})


def advice_for(
    code: ErrorCode, *, attempt: int = 0, retry_after: float | None = None
) -> RetryAdvice:
    if code not in _RETRYABLE:
        return RetryAdvice(retry=False, after_seconds=0.0, reason=code.value)
    attempt_n = max(0, int(attempt))
    if attempt_n >= 4:
        return RetryAdvice(retry=False, after_seconds=0.0, reason="exhausted")
    base = 0.4 * (2**attempt_n)
    wait = float(retry_after) if retry_after is not None else min(8.0, base)
    return RetryAdvice(retry=True, after_seconds=wait, reason=code.value)


def parse_retry_after(header: object) -> float | None:
    raw = str(header or "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    if value < 0:
        return None
    return min(value, 60.0)
