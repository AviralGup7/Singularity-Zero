"""Simple token-bucket rate limiter used by providers.

This is intentionally small and test-friendly: a blocking `acquire` call
that sleeps when tokens are exhausted. It's not perfect for distributed
systems but is adequate for local throttling in collectors.
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    def __init__(self, rate_per_second: float, capacity: int | None = None) -> None:
        self.rate = float(max(0.0, rate_per_second))
        self.capacity = int(capacity) if capacity is not None else max(1, int(self.rate))
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def _add_tokens(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        if elapsed <= 0:
            return
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last = now

    def try_acquire(self, tokens: int = 1) -> bool:
        with self._lock:
            self._add_tokens()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def acquire(self, tokens: int = 1) -> None:
        # blocking acquire
        while True:
            with self._lock:
                self._add_tokens()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                # compute wait time until enough tokens
                needed = tokens - self._tokens
                wait = max(0.01, needed / max(self.rate, 1e-6))
            time.sleep(wait)


# Global default limiter (can be overridden by tests)
DEFAULT_LIMITER = TokenBucket(rate_per_second=20.0, capacity=40)


def acquire(tokens: int = 1, limiter: TokenBucket | None = None) -> None:
    (limiter or DEFAULT_LIMITER).acquire(tokens)


def try_acquire(tokens: int = 1, limiter: TokenBucket | None = None) -> bool:
    return (limiter or DEFAULT_LIMITER).try_acquire(tokens)


__all__ = ["TokenBucket", "acquire", "try_acquire", "DEFAULT_LIMITER"]
