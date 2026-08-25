"""Adaptive Additive-Increase / Multiplicative-Decrease (AIMD) Rate Limiter.

Dynamically throttles per-host scan concurrency and backoff cooldowns when
target rate limits (HTTP 429), server load (HTTP 503), or latency spikes occur.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class HostConcurrencyState:
    """Per-host dynamic concurrency and backoff tracking state."""

    host: str
    current_concurrency: float = 4.0
    min_concurrency: float = 1.0
    max_concurrency: float = 16.0
    additive_increase: float = 1.0
    multiplicative_decrease: float = 0.5
    backoff_until: float = 0.0
    success_count_since_increase: int = 0
    successes_per_increase: int = 5
    consecutive_rate_limits: int = 0
    last_updated: float = field(default_factory=time.time)


class AdaptiveRateLimiter:
    """AIMD congestion controller for target rate limiting and concurrency tuning."""

    def __init__(
        self,
        default_concurrency: float = 4.0,
        min_concurrency: float = 1.0,
        max_concurrency: float = 16.0,
        multiplicative_decrease: float = 0.5,
    ) -> None:
        self.default_concurrency = default_concurrency
        self.min_concurrency = min_concurrency
        self.max_concurrency = max_concurrency
        self.multiplicative_decrease = multiplicative_decrease
        self._hosts: dict[str, HostConcurrencyState] = {}
        self._lock = threading.RLock()

    def _get_or_create(self, host: str) -> HostConcurrencyState:
        if host not in self._hosts:
            self._hosts[host] = HostConcurrencyState(
                host=host,
                current_concurrency=self.default_concurrency,
                min_concurrency=self.min_concurrency,
                max_concurrency=self.max_concurrency,
                multiplicative_decrease=self.multiplicative_decrease,
            )
        return self._hosts[host]

    def on_success(self, host: str) -> float:
        """Record successful request. Additively increase concurrency after N successes."""
        with self._lock:
            state = self._get_or_create(host)
            state.consecutive_rate_limits = 0
            state.success_count_since_increase += 1

            if state.success_count_since_increase >= state.successes_per_increase:
                state.current_concurrency = min(
                    state.max_concurrency,
                    state.current_concurrency + state.additive_increase,
                )
                state.success_count_since_increase = 0

            state.last_updated = time.time()
            return state.current_concurrency

    def on_rate_limit(self, host: str, retry_after: float | None = None) -> float:
        """Record HTTP 429/503. Multiplicatively decrease concurrency and set cooldown."""
        with self._lock:
            state = self._get_or_create(host)
            state.consecutive_rate_limits += 1
            state.success_count_since_increase = 0

            # Multiplicative decrease
            state.current_concurrency = max(
                state.min_concurrency,
                state.current_concurrency * state.multiplicative_decrease,
            )

            # Determine cooldown duration
            cooldown = retry_after if retry_after is not None and retry_after > 0 else min(60.0, 2.0 ** state.consecutive_rate_limits)
            state.backoff_until = time.time() + cooldown
            state.last_updated = time.time()

            logger.info(
                "AdaptiveRateLimiter: %s rate-limited, concurrency reduced to %.1f, backoff for %.1fs",
                host,
                state.current_concurrency,
                cooldown,
            )
            return state.current_concurrency

    def get_allowed_concurrency(self, host: str) -> int:
        """Return the effective integer worker slot limit for host."""
        with self._lock:
            state = self._get_or_create(host)
            if self.is_backed_off(host):
                return 0
            return max(1, int(state.current_concurrency))

    def is_backed_off(self, host: str) -> bool:
        """Return True if host is currently in rate-limit backoff cooldown."""
        with self._lock:
            state = self._hosts.get(host)
            if not state:
                return False
            return time.time() < state.backoff_until


__all__ = [
    "AdaptiveRateLimiter",
    "HostConcurrencyState",
]
