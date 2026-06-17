from __future__ import annotations

import logging
import time
from enum import StrEnum


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
