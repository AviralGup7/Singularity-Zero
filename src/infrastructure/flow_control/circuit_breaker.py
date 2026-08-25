"""Three-State Statistical Sliding-Window Circuit Breaker."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from enum import StrEnum


class CircuitState(StrEnum):
    CLOSED = "closed"  # Healthy: all traffic allowed
    OPEN = "open"  # Tripped: fast-fail all requests
    HALF_OPEN = "half_open"  # Canary testing after cooldown


class CircuitBreakerOpenError(Exception):
    """Raised when an operation is attempted on an open circuit breaker."""


@dataclass
class CircuitBreaker:
    """Statistical rolling-window circuit breaker protecting downstream targets."""

    name: str = "default"
    failure_threshold: float = 0.5  # 50% failure rate triggers open
    min_samples: int = 10
    recovery_cooldown_seconds: float = 15.0
    window_size: int = 20

    _state: CircuitState = CircuitState.CLOSED
    _history: deque[bool] = field(default_factory=lambda: deque(maxlen=20))
    _tripped_at: float = 0.0

    def __post_init__(self) -> None:
        self._history = deque(maxlen=self.window_size)

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.time() - self._tripped_at >= self.recovery_cooldown_seconds:
                self._state = CircuitState.HALF_OPEN
        return self._state

    def allow_request(self) -> bool:
        return self.state in {CircuitState.CLOSED, CircuitState.HALF_OPEN}

    def record_success(self) -> None:
        self._history.append(True)
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.CLOSED
            self._history.clear()

    def record_failure(self) -> None:
        self._history.append(False)
        if self._state == CircuitState.HALF_OPEN:
            # Canary failed -> reopen immediately
            self._state = CircuitState.OPEN
            self._tripped_at = time.time()
            return

        if len(self._history) >= self.min_samples:
            failures = sum(1 for success in self._history if not success)
            rate = failures / len(self._history)
            if rate >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._tripped_at = time.time()


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerOpenError",
    "CircuitState",
]
