"""
Rate-limiting and jitter utilities for mesh message sends.

Computes exponential back-off intervals with bounded +/- jitter
and exposes a send retry budget for _send_reliable.
"""

from __future__ import annotations

import random


class RateLimiter:
    """Exponential back-off with +/-25% jitter."""

    def __init__(self, base_ms: int = 100, max_ms: int = 2000, max_attempts: int = 5):
        self.base_ms = base_ms
        self.max_ms = max_ms
        self.max_attempts = max_attempts

    def interval_seconds(self, attempt: int) -> float:
        """Return the back-off interval in seconds for the given zero-based attempt."""
        base = min(self.max_ms, self.base_ms * (2**attempt))
        jittered = base * random.uniform(0.75, 1.25)
        return max(0.001, float(jittered / 1000.0))
