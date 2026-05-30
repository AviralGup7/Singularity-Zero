"""
Cyber Security Test Pipeline - Circuit Breaker
Implements a high-resilience circuit breaker to prevent cascading blocking failures.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, TypeVar, cast

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

T = TypeVar("T")


class CircuitBreakerOpenException(Exception):
    """Exception raised when the circuit breaker is OPEN and fails fast."""

    pass


class CircuitBreaker:
    """
    State machine for service circuit breakers.
    States: CLOSED (normal), OPEN (fail-fast), HALF_OPEN (probe request).
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 10.0,
        fallback_fn: Callable[..., Any] | None = None,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.fallback_fn = fallback_fn
        self.state = "CLOSED"
        self.failure_count = 0
        self.last_state_change = time.time()

    def call(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Execute protected function, handling state transitions and fallbacks."""
        now = time.time()

        # 1. State: OPEN -> Check Cooldown
        if self.state == "OPEN":
            if now - self.last_state_change > self.recovery_timeout:
                self.state = "HALF_OPEN"
                self.last_state_change = now
                logger.info(
                    "CircuitBreaker [%s]: Entering HALF_OPEN state. Testing service viability.",
                    self.name,
                )
            else:
                # Fail fast or route to fallback
                if self.fallback_fn:
                    return cast(T, self.fallback_fn(*args, **kwargs))
                raise CircuitBreakerOpenException(
                    f"Circuit Breaker [{self.name}] is currently OPEN. Failing fast."
                )

        # 2. Execute protected call
        try:
            result = fn(*args, **kwargs)

            # If successful in HALF_OPEN, heal to CLOSED
            if self.state == "HALF_OPEN":
                self.state = "CLOSED"
                self.failure_count = 0
                self.last_state_change = now
                logger.info(
                    "CircuitBreaker [%s]: Service recovered. Entering CLOSED state.", self.name
                )
            elif self.state == "CLOSED":
                self.failure_count = 0

            return result

        except Exception as exc:
            self.failure_count += 1
            self.last_state_change = now

            # Trip to OPEN if failure threshold is breached
            if (
                self.state in ("CLOSED", "HALF_OPEN")
                and self.failure_count >= self.failure_threshold
            ):
                self.state = "OPEN"
                logger.warning(
                    "CircuitBreaker [%s]: Tripped to OPEN due to %d consecutive failures: %s",
                    self.name,
                    self.failure_count,
                    exc,
                )

            if self.fallback_fn:
                return cast(T, self.fallback_fn(*args, **kwargs))
            raise exc
