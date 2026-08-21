"""Per-subject token bucket for mutating console commands."""

from __future__ import annotations

import threading
import time

from src.integration.errors import ErrorCode, IntegrationError


class TokenBucket:
    def __init__(self, *, rate: float = 8.0, burst: float = 16.0) -> None:
        self._rate = max(1.0, float(rate))
        self._burst = max(self._rate, float(burst))
        self._lock = threading.RLock()
        self._tokens: dict[str, tuple[float, float]] = {}

    def take(self, subject: str, *, cost: float = 1.0, now: float | None = None) -> None:
        epoch = float(now if now is not None else time.time())
        key = subject or "anonymous"
        with self._lock:
            tokens, last = self._tokens.get(key, (self._burst, epoch))
            tokens = min(self._burst, tokens + (epoch - last) * self._rate)
            if tokens < cost:
                raise IntegrationError(
                    ErrorCode.RATE_LIMITED,
                    "too many console commands",
                    details={"retry_after": round((cost - tokens) / self._rate, 3)},
                )
            self._tokens[key] = (tokens - cost, epoch)
