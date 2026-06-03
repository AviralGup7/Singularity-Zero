"""
Cyber Security Test Pipeline - Circuit Breaker
Implements a high-resilience circuit breaker to prevent cascading blocking failures.
"""

from __future__ import annotations

import inspect
import threading
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar, cast

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

T = TypeVar("T")


class CircuitBreakerOpenException(Exception):
    """Exception raised when the circuit breaker is OPEN and fails fast."""

    pass


class _ProbeAborted(BaseException):
    """Internal marker for HALF_OPEN probe cancellation (inherits BaseException)."""

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
        self.last_state_change = time.monotonic()
        self._lock = threading.RLock()
        self._state_version = 0
        self._half_open_probe_in_flight = False

    def call(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Execute protected function, handling state transitions and fallbacks."""
        admitted, admission_state, state_version = self._try_admit_call()
        if not admitted:
            return cast(T, self._fallback_or_raise(*args, **kwargs))

        # 2. Execute protected call
        try:
            result = fn(*args, **kwargs)
        except BaseException as exc:
            if isinstance(exc, Exception):
                self._record_failure(admission_state, state_version, exc)
                if self.fallback_fn:
                    return cast(T, self.fallback_fn(*args, **kwargs))
            else:
                self._release_aborted_probe(admission_state, state_version)
            raise

        if inspect.isawaitable(result):
            return cast(
                T,
                self._await_result(
                    cast(Awaitable[Any], result),
                    admission_state,
                    state_version,
                    args,
                    kwargs,
                ),
            )

        self._record_success(admission_state, state_version)
        return result

    async def call_async(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute a protected sync or async callable and await async results safely."""
        admitted, admission_state, state_version = self._try_admit_call()
        if not admitted:
            return await self._fallback_or_raise_async(*args, **kwargs)

        try:
            result = fn(*args, **kwargs)
            if inspect.isawaitable(result):
                result = await result
        except BaseException as exc:
            if isinstance(exc, Exception):
                self._record_failure(admission_state, state_version, exc)
                if self.fallback_fn:
                    return await self._call_fallback_async(*args, **kwargs)
            else:
                self._release_aborted_probe(admission_state, state_version)
            raise

        self._record_success(admission_state, state_version)
        return result

    def _try_admit_call(self) -> tuple[bool, str, int]:
        with self._lock:
            now = time.monotonic()

            if self.state == "OPEN" and now - self.last_state_change >= self.recovery_timeout:
                self._transition_to("HALF_OPEN", now)
                self._half_open_probe_in_flight = False
                logger.info(
                    "CircuitBreaker [%s]: Entering HALF_OPEN state. Testing service viability.",
                    self.name,
                )

            if self.state == "OPEN":
                return False, self.state, self._state_version

            if self.state == "HALF_OPEN":
                if self._half_open_probe_in_flight:
                    return False, self.state, self._state_version
                self._half_open_probe_in_flight = True

            return True, self.state, self._state_version

    def _record_success(self, admission_state: str, state_version: int) -> None:
        with self._lock:
            if self._state_version != state_version:
                return

            if admission_state == "HALF_OPEN" and self.state == "HALF_OPEN":
                self._half_open_probe_in_flight = False
                self.failure_count = 0
                self._transition_to("CLOSED", time.monotonic())
                logger.info(
                    "CircuitBreaker [%s]: Service recovered. Entering CLOSED state.", self.name
                )
            elif admission_state == "CLOSED" and self.state == "CLOSED":
                self.failure_count = 0

    def _record_failure(self, admission_state: str, state_version: int, exc: Exception) -> None:
        with self._lock:
            if self._state_version != state_version:
                return

            if admission_state == "HALF_OPEN" and self.state == "HALF_OPEN":
                self._half_open_probe_in_flight = False
                self.failure_count += 1
                self._trip_open(exc)
            elif admission_state == "CLOSED" and self.state == "CLOSED":
                self.failure_count += 1
                if self.failure_count >= max(1, self.failure_threshold):
                    self._trip_open(exc)

    def _release_aborted_probe(self, admission_state: str, state_version: int) -> None:
        with self._lock:
            if (
                admission_state == "HALF_OPEN"
                and self.state == "HALF_OPEN"
                and self._state_version == state_version
            ):
                self._half_open_probe_in_flight = False

    def _trip_open(self, exc: Exception) -> None:
        self._transition_to("OPEN", time.monotonic())
        logger.warning(
            "CircuitBreaker [%s]: Tripped to OPEN due to %d consecutive failures: %s",
            self.name,
            self.failure_count,
            exc,
        )

    def _transition_to(self, state: str, now: float) -> None:
        if self.state != state:
            self.state = state
            self.last_state_change = now
            self._state_version += 1

    def _fallback_or_raise(self, *args: Any, **kwargs: Any) -> Any:
        if self.fallback_fn:
            return self.fallback_fn(*args, **kwargs)
        raise CircuitBreakerOpenException(
            f"Circuit Breaker [{self.name}] is currently OPEN. Failing fast."
        )

    async def _fallback_or_raise_async(self, *args: Any, **kwargs: Any) -> Any:
        if self.fallback_fn:
            return await self._call_fallback_async(*args, **kwargs)
        raise CircuitBreakerOpenException(
            f"Circuit Breaker [{self.name}] is currently OPEN. Failing fast."
        )

    async def _call_fallback_async(self, *args: Any, **kwargs: Any) -> Any:
        result = self.fallback_fn(*args, **kwargs) if self.fallback_fn else None
        if inspect.isawaitable(result):
            return await result
        return result

    async def _await_result(
        self,
        result: Awaitable[Any],
        admission_state: str,
        state_version: int,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any:
        try:
            value = await result
        except BaseException as exc:
            if isinstance(exc, Exception):
                self._record_failure(admission_state, state_version, exc)
                if self.fallback_fn:
                    return await self._call_fallback_async(*args, **kwargs)
            else:
                self._release_aborted_probe(admission_state, state_version)
            raise

        self._record_success(admission_state, state_version)
        return value
