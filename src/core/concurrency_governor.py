"""Global concurrency governor for cross-subsystem coordination.

Prevents the system-wide feedback loop where each subsystem (EventBus,
ResourcePool, Queue, Mesh, ParallelAnalyzers, Cache) independently
thinks it is within its own limit while collectively exhausting CPU/RAM.

Subsystem usage::

    from src.core.concurrency_governor import get_governor

    governor = get_governor()

    # Before creating heavy work:
    if not governor.allow("event_bus"):
        logger.warning("Global limit reached, dropping event")
        return

    # After work completes:
    governor.release("event_bus")

The governor is deliberately lightweight — a threading.Lock-protected
counter and per-subsystem tracking — so it never becomes a bottleneck
itself.
"""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger(__name__)

# Defaults — overridable via environment or constructor.
_DEFAULT_GLOBAL_MAX_TASKS = 1024
_DEFAULT_SUBSYSTEM_MAX_RATIO = 0.5  # no single subsystem may use > 50%


class ConcurrencyGovernor:
    """Process-wide governor that caps total concurrent work across subsystems.

    Attributes:
        global_max: Absolute ceiling on concurrent tasks.
        subsystem_max_ratio: Maximum fraction of ``global_max`` any single
            subsystem may hold.
    """

    def __init__(
        self,
        global_max: int = _DEFAULT_GLOBAL_MAX_TASKS,
        subsystem_max_ratio: float = _DEFAULT_SUBSYSTEM_MAX_RATIO,
    ) -> None:
        self.global_max = global_max
        self.subsystem_max_ratio = subsystem_max_ratio
        self._lock = threading.Lock()
        self._total: int = 0
        self._per_subsystem: dict[str, int] = {}
        self._total_dropped: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def allow(self, subsystem: str) -> bool:
        """Return ``True`` if a new task from *subsystem* is permitted.

        Increments the global and per-subsystem counters when allowed.
        """
        with self._lock:
            if self._total >= self.global_max:
                self._total_dropped += 1
                if self._total_dropped % 100 == 1:
                    logger.warning(
                        "Concurrency governor: global limit %d reached "
                        "(total=%d, subsystem=%s). %d tasks dropped so far.",
                        self.global_max,
                        self._total,
                        subsystem,
                        self._total_dropped,
                    )
                return False

            sub_count = self._per_subsystem.get(subsystem, 0)
            sub_limit = int(self.global_max * self.subsystem_max_ratio)
            if sub_count >= sub_limit:
                self._total_dropped += 1
                if self._total_dropped % 100 == 1:
                    logger.warning(
                        "Concurrency governor: subsystem '%s' limit %d reached "
                        "(count=%d). %d tasks dropped so far.",
                        subsystem,
                        sub_limit,
                        sub_count,
                        self._total_dropped,
                    )
                return False

            self._total += 1
            self._per_subsystem[subsystem] = sub_count + 1
            return True

    def release(self, subsystem: str) -> None:
        """Mark one task from *subsystem* as complete."""
        with self._lock:
            if self._total > 0:
                self._total -= 1
            sub_count = self._per_subsystem.get(subsystem, 0)
            if sub_count > 1:
                self._per_subsystem[subsystem] = sub_count - 1
            elif sub_count == 1:
                self._per_subsystem.pop(subsystem, None)

    @contextmanager
    def capacity(self, subsystem: str):
        """Context manager that acquires a slot and auto-releases on exit.

        Prevents capacity leaks from unhandled exceptions::

            with governor.capacity("actor_scheduler"):
                await heavy_work()

        If ``allow()`` returns False, raises ``RuntimeError``.
        """
        if not self.allow(subsystem):
            raise RuntimeError(
                f"Concurrency governor: capacity denied for subsystem '{subsystem}'"
            )
        try:
            yield
        finally:
            self.release(subsystem)

    def snapshot(self) -> dict[str, Any]:
        """Return a diagnostic snapshot (thread-safe)."""
        with self._lock:
            return {
                "global_max": self.global_max,
                "total_active": self._total,
                "total_dropped": self._total_dropped,
                "per_subsystem": dict(self._per_subsystem),
            }

    def adjust_global_max(self, new_max: int) -> None:
        """Dynamically adjust the global ceiling (e.g. based on system load)."""
        if new_max < 1:
            raise ValueError("global_max must be >= 1")
        with self._lock:
            old = self.global_max
            self.global_max = new_max
        logger.info(
            "Concurrency governor global_max adjusted: %d -> %d", old, new_max
        )


_governor: ConcurrencyGovernor | None = None
_governor_lock = threading.Lock()


def get_governor() -> ConcurrencyGovernor:
    """Return the process-wide ConcurrencyGovernor singleton."""
    global _governor
    with _governor_lock:
        if _governor is None:
            _governor = ConcurrencyGovernor()
        return _governor


def reset_governor() -> None:
    """Reset the singleton (primarily for tests)."""
    global _governor
    with _governor_lock:
        _governor = None
