"""Regression: limit_override=0 must not fall back to the default limit."""

from __future__ import annotations

import pytest

from src.dashboard.rate_limiter import InMemoryRateLimiter, RateLimitConfig


@pytest.mark.asyncio
@pytest.mark.unit
async def test_zero_limit_override_denies() -> None:
    limiter = InMemoryRateLimiter(RateLimitConfig(default_limit=60, window_seconds=60))
    allowed, remaining, retry = await limiter.check("1.2.3.4", "/api/x", limit_override=0)
    assert allowed is False
    assert remaining == 0
    assert retry is not None


@pytest.mark.asyncio
@pytest.mark.unit
async def test_none_override_uses_default() -> None:
    limiter = InMemoryRateLimiter(RateLimitConfig(default_limit=2, window_seconds=60))
    ok1, rem1, _ = await limiter.check("1.2.3.4", "/api/x", limit_override=None)
    ok2, rem2, _ = await limiter.check("1.2.3.4", "/api/x", limit_override=None)
    ok3, rem3, retry = await limiter.check("1.2.3.4", "/api/x", limit_override=None)
    assert (ok1, rem1) == (True, 1)
    assert (ok2, rem2) == (True, 0)
    assert ok3 is False
    assert rem3 == 0
    assert retry is not None
