"""Canonical per-tool circuit breaker.

``src.pipeline.retry.circuit_breaker`` re-exports this module. Persistence
hooks live here so the scheduler and dashboard share one snapshot format.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class ToolCircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout: float = 300.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failures: dict[str, list[float]] = {}
        self._state: dict[str, CircuitState] = {}
        self._opened_at: dict[str, float] = {}
        self._skip_reason: dict[str, str] = {}
        self._half_open_trial_used: dict[str, bool] = {}
        self._logger = logging.getLogger(__name__)

    def record_success(self, tool_name: str) -> None:
        state = self._state.get(tool_name, CircuitState.CLOSED)
        if state == CircuitState.HALF_OPEN:
            self._logger.info("Tool '%s' recovered, closing circuit.", tool_name)
        self._failures.pop(tool_name, None)
        self._state[tool_name] = CircuitState.CLOSED
        self._opened_at.pop(tool_name, None)
        self._skip_reason.pop(tool_name, None)
        self._half_open_trial_used.pop(tool_name, None)

    def record_failure(self, tool_name: str, error_type: str) -> None:
        state = self._state.get(tool_name, CircuitState.CLOSED)
        if state == CircuitState.HALF_OPEN:
            self._logger.warning(
                "Tool '%s' half-open trial failed (%s), reopening circuit.", tool_name, error_type
            )
            self._state[tool_name] = CircuitState.OPEN
            self._opened_at[tool_name] = time.monotonic()
            self._failures[tool_name] = [time.monotonic()]
            self._half_open_trial_used[tool_name] = False
            self._skip_reason[tool_name] = (
                f"Circuit open for '{tool_name}' after consecutive failure (half-open trial failed: {error_type})"
            )
            return
        if state == CircuitState.OPEN:
            return
        now = time.monotonic()
        timestamps = self._failures.setdefault(tool_name, [])
        cutoff = now - self.recovery_timeout
        timestamps[:] = [ts for ts in timestamps if ts > cutoff]
        timestamps.append(now)
        if len(timestamps) >= self.failure_threshold:
            self._state[tool_name] = CircuitState.OPEN
            self._opened_at[tool_name] = now
            self._half_open_trial_used[tool_name] = False
            self._skip_reason[tool_name] = (
                f"Circuit open for '{tool_name}' after {self.failure_threshold} consecutive failures within {self.recovery_timeout}s"
            )
            self._logger.warning(
                "Circuit OPENED for tool '%s' after %d failures.", tool_name, self.failure_threshold
            )

    def can_execute(self, tool_name: str) -> bool:
        state = self._state.get(tool_name, CircuitState.CLOSED)
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.HALF_OPEN:
            return False
        now = time.monotonic()
        opened_at = self._opened_at.get(tool_name, 0.0)
        if now - opened_at >= self.recovery_timeout:
            self._state[tool_name] = CircuitState.HALF_OPEN
            self._opened_at[tool_name] = now
            if self._half_open_trial_used.get(tool_name, False):
                self._state[tool_name] = CircuitState.OPEN
                self._failures[tool_name] = [now]
                self._half_open_trial_used[tool_name] = False
                self._skip_reason[tool_name] = (
                    f"Circuit open for '{tool_name}' after consecutive failure (half-open trial already used)"
                )
                return False
            self._logger.info("Circuit for tool '%s' entering HALF_OPEN for trial.", tool_name)
            return True
        return False

    def get_state(self, tool_name: str) -> CircuitState:
        self._maybe_refresh_half_open(tool_name)
        return self._state.get(tool_name, CircuitState.CLOSED)

    def get_skip_reason(self, tool_name: str) -> str | None:
        self._maybe_refresh_half_open(tool_name)
        return self._skip_reason.get(tool_name)

    def _maybe_refresh_half_open(self, tool_name: str) -> None:
        state = self._state.get(tool_name)
        if state != CircuitState.HALF_OPEN:
            return
        now = time.monotonic()
        opened_at = self._opened_at.get(tool_name, 0.0)
        if now - opened_at < self.recovery_timeout:
            return
        self._state[tool_name] = CircuitState.OPEN
        self._opened_at[tool_name] = now
        self._failures[tool_name] = [now]
        self._half_open_trial_used[tool_name] = False
        self._skip_reason[tool_name] = (
            f"Circuit open for '{tool_name}' after consecutive failure (half-open trial expired)"
        )

    def snapshot(self) -> dict[str, Any]:
        """Serializable per-tool state for WAL / SQLite persistence."""
        tools: dict[str, Any] = {}
        names = set(self._state) | set(self._failures) | set(self._opened_at)
        for name in names:
            tools[name] = {
                "state": self._state.get(name, CircuitState.CLOSED).value,
                "failures": list(self._failures.get(name, [])),
                "opened_at": self._opened_at.get(name),
                "skip_reason": self._skip_reason.get(name),
                "half_open_trial_used": self._half_open_trial_used.get(name, False),
            }
        return {
            "failure_threshold": self.failure_threshold,
            "recovery_timeout": self.recovery_timeout,
            "tools": tools,
        }

    def restore(self, payload: dict[str, Any]) -> None:
        """Load a ``snapshot()`` payload. Unknown keys are ignored."""
        self.failure_threshold = int(payload.get("failure_threshold", self.failure_threshold))
        self.recovery_timeout = float(payload.get("recovery_timeout", self.recovery_timeout))
        tools = payload.get("tools") or {}
        self._failures.clear()
        self._state.clear()
        self._opened_at.clear()
        self._skip_reason.clear()
        self._half_open_trial_used.clear()
        for name, raw in tools.items():
            if not isinstance(raw, dict):
                continue
            state_raw = str(raw.get("state") or CircuitState.CLOSED.value)
            try:
                self._state[name] = CircuitState(state_raw)
            except ValueError:
                self._state[name] = CircuitState.CLOSED
            failures = raw.get("failures") or []
            self._failures[name] = [float(ts) for ts in failures]
            opened_at = raw.get("opened_at")
            if opened_at is not None:
                self._opened_at[name] = float(opened_at)
            skip_reason = raw.get("skip_reason")
            if skip_reason:
                self._skip_reason[name] = str(skip_reason)
            self._half_open_trial_used[name] = bool(raw.get("half_open_trial_used", False))


@dataclass(slots=True, frozen=True)
class CircuitBreakerStats:
    """Serializable snapshot of a circuit breaker's state."""

    name: str
    state: str
    failure_count: int
    failure_threshold: int
    recovery_timeout: float
    last_failure_time: float
    last_state_change: float
    force_open_until: float
    forced_open: bool
    probe_registered: bool
    total_successes: int
    total_failures: int
    total_forced_opens: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


ProbeCallback = Callable[["CircuitBreaker"], None]


class CircuitBreakerOpenError(Exception):
    """Raised when an operation is attempted on an open circuit breaker."""


class CircuitBreaker:
    """Per-instance or per-host circuit breaker with statistical and consecutive failure protection."""

    def __init__(
        self,
        name: str = "default",
        failure_threshold: int | float = 5,
        recovery_timeout: float = 60.0,
        min_samples: int = 10,
        window_size: int = 20,
    ) -> None:
        self.name = name
        self._is_statistical = (
            isinstance(failure_threshold, float) and 0.0 < failure_threshold < 1.0
        )
        self.failure_threshold = failure_threshold
        self.recovery_timeout = max(0.0, float(recovery_timeout))
        self.recovery_cooldown_seconds = self.recovery_timeout
        self.min_samples = min_samples
        self.window_size = window_size
        self._logger = logging.getLogger(__name__)

        self._failure_count: int = 0
        self._last_failure_time: float = 0.0
        self._last_state_change: float = time.time()
        self._state: str = CircuitState.CLOSED.value
        self._lock = threading.Lock()
        self._history: deque[bool] = deque(maxlen=window_size)

        self._cached_state: str = CircuitState.CLOSED.value
        self._cached_state_time: float = 0.0
        self._cache_ttl: float = 0.05

        self._force_open_until: float = 0.0
        self._forced_open: bool = False
        self._probe_callback: ProbeCallback | None = None
        self._probe_pending: bool = False

        self._total_successes: int = 0
        self._total_failures: int = 0
        self._total_forced_opens: int = 0

    @property
    def state(self) -> str:
        now = time.time()
        if now - self._cached_state_time < self._cache_ttl:
            return self._cached_state

        with self._lock:
            if self._state == CircuitState.OPEN.value:
                if self._forced_open and now < self._force_open_until:
                    pass
                elif now - self._last_failure_time >= self.recovery_timeout:
                    self._set_state_locked(CircuitState.HALF_OPEN.value, now, log=True)
                    self._probe_pending = True

            self._cached_state = self._state
            self._cached_state_time = now
            return self._state

    def is_closed(self) -> bool:
        return self.state == CircuitState.CLOSED.value

    def is_open(self) -> bool:
        return self.state == CircuitState.OPEN.value

    def is_half_open(self) -> bool:
        return self.state == CircuitState.HALF_OPEN.value

    def allow_request(self) -> bool:
        return self.can_execute()

    def record_success(self) -> None:
        with self._lock:
            self._total_successes += 1
            self._history.append(True)
            if self._state in (CircuitState.HALF_OPEN.value, CircuitState.CLOSED.value):
                self._failure_count = 0
                self._set_state_locked(CircuitState.CLOSED.value, time.time(), log=False)
                if self._forced_open:
                    self._forced_open = False
                    self._force_open_until = 0.0

    def record_failure(self) -> None:
        with self._lock:
            now = time.time()
            self._total_failures += 1
            self._failure_count += 1
            self._last_failure_time = now
            self._history.append(False)

            if self._state == CircuitState.HALF_OPEN.value:
                self._set_state_locked(CircuitState.OPEN.value, now, log=True)
                return

            if self._is_statistical:
                if len(self._history) >= self.min_samples:
                    failures = sum(1 for success in self._history if not success)
                    rate = failures / len(self._history)
                    if rate >= float(self.failure_threshold):
                        self._set_state_locked(CircuitState.OPEN.value, now, log=True)
            else:
                if self._failure_count >= int(self.failure_threshold):
                    self._set_state_locked(CircuitState.OPEN.value, now, log=True)

    def can_execute(self) -> bool:
        with self._lock:
            now = time.time()
            if self._state == CircuitState.OPEN.value:
                if self._forced_open and now < self._force_open_until:
                    self._cached_state = CircuitState.OPEN.value
                    self._cached_state_time = now
                    return False
                if now - self._last_failure_time >= self.recovery_timeout:
                    self._set_state_locked(CircuitState.HALF_OPEN.value, now, log=True)
                    self._probe_pending = True
            if self._state == CircuitState.OPEN.value:
                self._cached_state = CircuitState.OPEN.value
                self._cached_state_time = now
                return False
            if self._state == CircuitState.HALF_OPEN.value:
                if not self._probe_pending and self._failure_count > 0:
                    self._cached_state = CircuitState.HALF_OPEN.value
                    self._cached_state_time = now
                    return False
                self._probe_pending = False
            return True

    def reset(self) -> None:
        with self._lock:
            now = time.time()
            self._failure_count = 0
            self._forced_open = False
            self._force_open_until = 0.0
            self._probe_pending = False
            self._history.clear()
            self._set_state_locked(CircuitState.CLOSED.value, now, log=True)

    def force_open(self, reason: str, duration_seconds: float | None = None) -> None:
        with self._lock:
            now = time.time()
            self._total_forced_opens += 1
            if duration_seconds is None or duration_seconds <= 0:
                self._force_open_until = float("inf")
            else:
                self._force_open_until = now + float(duration_seconds)
            self._forced_open = True
            threshold_int = (
                int(self.failure_threshold) if not self._is_statistical else self.min_samples
            )
            self._failure_count = max(self._failure_count, threshold_int)
            self._last_failure_time = now
            self._set_state_locked(CircuitState.OPEN.value, now, log=False)
            self._logger.warning(
                "Circuit breaker [%s] force-opened: %s (until=%s)",
                self.name,
                reason,
                self._force_open_until if self._force_open_until != float("inf") else "manual",
            )

    def update_recovery_timeout(self, recovery_timeout: float) -> None:
        if recovery_timeout < 0:
            raise ValueError("recovery_timeout must be >= 0")
        with self._lock:
            self.recovery_timeout = float(recovery_timeout)
            self.recovery_cooldown_seconds = self.recovery_timeout

    def schedule_recovery_probe(self, callback: ProbeCallback) -> None:
        with self._lock:
            self._probe_callback = callback

    def consume_pending_probe(self) -> ProbeCallback | None:
        with self._lock:
            if not self._probe_pending:
                return None
            self._probe_pending = False
            return self._probe_callback

    def stats(self) -> CircuitBreakerStats:
        with self._lock:
            threshold_int = (
                int(self.failure_threshold) if not self._is_statistical else self.min_samples
            )
            return CircuitBreakerStats(
                name=self.name,
                state=self._state,
                failure_count=self._failure_count,
                failure_threshold=threshold_int,
                recovery_timeout=self.recovery_timeout,
                last_failure_time=self._last_failure_time,
                last_state_change=self._last_state_change,
                force_open_until=(
                    self._force_open_until if self._force_open_until != float("inf") else 0.0
                ),
                forced_open=self._forced_open,
                probe_registered=self._probe_callback is not None,
                total_successes=self._total_successes,
                total_failures=self._total_failures,
                total_forced_opens=self._total_forced_opens,
            )

    def _set_state_locked(self, new_state: str, now: float, *, log: bool) -> None:
        if self._state == new_state:
            return
        old = self._state
        self._state = new_state
        self._last_state_change = now
        self._cached_state = new_state
        self._cached_state_time = now
        if log:
            self._logger.info(
                "Circuit breaker [%s] %s -> %s",
                self.name,
                old,
                new_state,
            )


@dataclass(slots=True, frozen=True)
class CircuitBreakerConfig:
    """Per-tool circuit-breaker tunables."""

    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    force_open_initial: bool = False
    force_open_duration_seconds: float = 0.0
    force_open_reason: str = ""

    @classmethod
    def from_settings(
        cls,
        settings: dict[str, Any] | None,
        *,
        default: CircuitBreakerConfig | None = None,
    ) -> CircuitBreakerConfig:
        settings = settings or {}
        base = default or cls()
        try:
            threshold = int(
                settings.get("circuit_breaker_failure_threshold", base.failure_threshold)
            )
        except (TypeError, ValueError):
            threshold = base.failure_threshold
        try:
            recovery = float(
                settings.get("circuit_breaker_recovery_timeout", base.recovery_timeout)
            )
        except (TypeError, ValueError):
            recovery = base.recovery_timeout
        return cls(
            failure_threshold=max(1, threshold),
            recovery_timeout=max(0.0, recovery),
            force_open_initial=bool(
                settings.get("circuit_breaker_force_open", base.force_open_initial)
            ),
            force_open_duration_seconds=float(
                settings.get(
                    "circuit_breaker_force_open_duration",
                    base.force_open_duration_seconds,
                )
            ),
            force_open_reason=str(
                settings.get("circuit_breaker_force_open_reason", base.force_open_reason)
            ),
        )


_CB_PERSISTENCE_PREFIX = "cb_state:"


def persist_breaker_state(cache: Any, tool_name: str, breaker: CircuitBreaker) -> None:
    """Persist a circuit breaker's serializable state to unified cache."""
    try:
        cache.set(
            f"{_CB_PERSISTENCE_PREFIX}{tool_name}",
            breaker.stats().as_dict(),
            ttl=86400 * 30,
            priority="critical",
        )
    except Exception as exc:
        logging.warning("Operation failed in persist_breaker_state: %s", exc, exc_info=True)


def load_breaker_state(cache: Any, tool_name: str) -> dict[str, Any] | None:
    """Load persisted circuit breaker state. Returns None if absent."""
    try:
        raw = cache.get(f"{_CB_PERSISTENCE_PREFIX}{tool_name}")
        return raw if isinstance(raw, dict) else None
    except Exception:
        return None


def persist_all_breakers(cache: Any, breakers: dict[str, CircuitBreaker]) -> None:
    for name, breaker in breakers.items():
        persist_breaker_state(cache, name, breaker)


def load_all_breakers(cache: Any) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    try:
        prefix = _CB_PERSISTENCE_PREFIX
        keys = cache.keys_with_prefix(prefix)
        for key in keys:
            name = key[len(prefix) :]
            state = cache.get(key)
            if isinstance(state, dict):
                result[name] = state
    except Exception as exc:
        logging.warning("Operation failed in load_all_breakers: %s", exc, exc_info=True)
    return result


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerOpenError",
    "CircuitBreakerStats",
    "CircuitState",
    "ProbeCallback",
    "ToolCircuitBreaker",
    "load_all_breakers",
    "load_breaker_state",
    "persist_all_breakers",
    "persist_breaker_state",
]
