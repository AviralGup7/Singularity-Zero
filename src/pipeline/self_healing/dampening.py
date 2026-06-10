"""Dampening window for suppressing duplicate corrective actions."""

from __future__ import annotations

import logging
import time
from threading import Lock

from src.core.contracts.health import CorrectiveAction, HealthComponent

logger = logging.getLogger(__name__)


class DampeningWindow:
    """Suppresses re-fires of the same corrective action for a given
    (action_type, component) tuple within a configurable cool-down.

    This prevents cascade failures from flapping stages.
    """

    def __init__(self, default_cooldown_seconds: float = 120.0) -> None:
        self._default_cooldown_seconds = default_cooldown_seconds
        self._last_fired: dict[tuple[CorrectiveAction, HealthComponent], float] = {}
        self._overrides: dict[tuple[CorrectiveAction, HealthComponent], float] = {}
        self._lock = Lock()

    def configure_cooldown(
        self,
        action: CorrectiveAction,
        component: HealthComponent,
        cooldown_seconds: float,
    ) -> None:
        with self._lock:
            self._overrides[(action, component)] = cooldown_seconds

    def clear(self) -> None:
        with self._lock:
            self._last_fired.clear()
            self._overrides.clear()

    def should_suppress(
        self,
        action: CorrectiveAction,
        component: HealthComponent,
        *,
        now: float | None = None,
    ) -> bool:
        key = (action, component)
        effective_cooldown = self._override_cooldown(key)
        last = self._last_fired.get(key)
        if last is None:
            return False
        current = now if now is not None else time.time()
        return (current - last) < effective_cooldown

    def record_fire(
        self,
        action: CorrectiveAction,
        component: HealthComponent,
        *,
        now: float | None = None,
    ) -> None:
        key = (action, component)
        current = now if now is not None else time.time()
        with self._lock:
            self._last_fired[key] = current

    def _override_cooldown(self, key: tuple[CorrectiveAction, HealthComponent]) -> float:
        override = self._overrides.get(key)
        if override is not None:
            return override
        action = key[0]
        if action == CorrectiveAction.REFRESH_STUCK_STAGE:
            return 120.0
        if action == CorrectiveAction.ESCALATE_ANALYST:
            return 300.0
        if action == CorrectiveAction.TRIP_TOOL_CIRCUIT_BREAKER:
            return 60.0
        return self._default_cooldown_seconds
