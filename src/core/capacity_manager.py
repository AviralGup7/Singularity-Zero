"""Unified CapacityManager — bridges ResourceGuard, ConcurrencyGovernor, and TaskRegistry.

The four independent capacity systems (ResourceGuard for RAM, ConcurrencyGovernor
for task slots, TaskRegistry for task tracking, ActorScheduler for dispatch) previously
made decisions without consulting each other. This module provides a single entry
point for all dispatch decisions.

Usage::

    from src.core.capacity_manager import get_capacity_manager

    manager = get_capacity_manager()

    # Before dispatching a task:
    ok, reason = manager.can_dispatch(
        subsystem="actor_scheduler",
        estimated_ram_mb=512,
        stage_name="full_scan",
    )
    if not ok:
        logger.warning("Dispatch denied: %s", reason)
        return

    # After task completes:
    manager.release("actor_scheduler")
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)

# Defaults — overridable via constructor
_DEFAULT_RESERVE_RAM_MB = 2048
_DEFAULT_IN_FLIGHT_AVG_RAM_MB = 512


class CapacityManager:
    """Unified capacity gate that coordinates RAM, concurrency slots, and task tracking.

    Attributes:
        reserve_ram_mb: RAM reserved for the system (not available for tasks).
        in_flight_avg_ram_mb: Conservative estimate of RAM per in-flight task
            when ResourceGuard can't provide precise per-task estimates.
    """

    def __init__(
        self,
        reserve_ram_mb: int = _DEFAULT_RESERVE_RAM_MB,
        in_flight_avg_ram_mb: int = _DEFAULT_IN_FLIGHT_AVG_RAM_MB,
        resource_guard: Any | None = None,
    ) -> None:
        self.reserve_ram_mb = reserve_ram_mb
        self.in_flight_avg_ram_mb = in_flight_avg_ram_mb
        self._resource_guard = resource_guard
        self._lock = threading.Lock()
        self._denied_count: int = 0
        self._allowed_count: int = 0
        self._last_denial: str | None = None

    def can_dispatch(
        self,
        subsystem: str,
        estimated_ram_mb: int = 0,
        stage_name: str | None = None,
    ) -> tuple[bool, str | None]:
        """Check if a new task can be dispatched from *subsystem*.

        Checks in order:
        1. ResourceGuard — is there enough RAM?
        2. ConcurrencyGovernor — are there available slots?
        3. TaskRegistry — sanity check on active task count

        Returns:
            (True, None) if dispatch is allowed.
            (False, reason) if denied.
        """
        # 1. RAM check via ResourceGuard
        if estimated_ram_mb > 0:
            try:
                guard = self._resource_guard
                if guard is None:
                    from src.infrastructure.resource_guard import ResourceGuard

                    guard = ResourceGuard()

                ok, reason = guard.check_available_ram_for_dispatch(
                    estimated_ram_mb=estimated_ram_mb,
                    in_flight_count=self._get_in_flight_count(),
                    in_flight_avg_ram_mb=self.in_flight_avg_ram_mb,
                )
                if not ok:
                    self._record_denial(f"ram: {reason}")
                    return False, reason
            except ImportError:
                logger.warning("Operation failed in capacity_manager.py", exc_info=True)
            except Exception as exc:
                logger.warning("CapacityManager: ResourceGuard check failed: %s", exc)
                reason = f"ram_check_error: {exc}"
                self._record_denial(reason)
                return False, reason

        # 2. Concurrency slot check
        # Bug fix: Check capacity WITHOUT acquiring the slot. Previously,
        # governor.allow() acquired the slot during the check, but if the
        # caller didn't dispatch (early return, exception), the slot leaked
        # permanently, eventually stalling the pipeline.
        try:
            from src.core.concurrency_governor import get_governor

            governor = get_governor()
            # Use check_available() if it exists, otherwise fall back to allow/release
            if hasattr(governor, "check_available"):
                if not governor.check_available(subsystem):
                    reason = f"concurrency_governor: global_max={governor.global_max} reached"
                    self._record_denial(reason)
                    return False, reason
            else:
                # Fallback: acquire then immediately release to check capacity
                if not governor.allow(subsystem):
                    reason = f"concurrency_governor: global_max={governor.global_max} reached"
                    self._record_denial(reason)
                    return False, reason
                # Slot acquired by the check — release immediately so the
                # caller can re-acquire when actually dispatching.
                governor.release(subsystem)
        except ImportError:
            logger.warning("Operation failed in capacity_manager.py", exc_info=True)
        except Exception as exc:
            logger.warning("CapacityManager: ConcurrencyGovernor check failed: %s", exc)
            reason = f"concurrency_check_error: {exc}"
            self._record_denial(reason)
            return False, reason

        # 3. TaskRegistry sanity check — if there are way more active tasks
        # than the concurrency governor allows, something is wrong.
        try:
            from src.core.task_registry import get_task_registry

            registry = get_task_registry()
            active = registry.active_count()
            # If active tasks exceed 2x the governor's global_max, block new dispatches
            try:
                from src.core.concurrency_governor import get_governor

                governor_max = get_governor().global_max
            except (ImportError, Exception):
                governor_max = 1024  # fallback

            if active > governor_max * 2:
                reason = (
                    f"task_registry: active_count={active} exceeds "
                    f"2x governor_max={governor_max} — possible task leak"
                )
                self._record_denial(reason)
                return False, reason
        except ImportError:
            logger.warning("Operation failed in capacity_manager.py", exc_info=True)
        except Exception as exc:
            logger.warning("CapacityManager: TaskRegistry check failed: %s", exc)

        with self._lock:
            self._allowed_count += 1
        return True, None

    def release(self, subsystem: str) -> None:
        """Release a concurrency slot after task completion.

        Must be called for every successful can_dispatch() that resulted
        in an actual task being started.
        """
        try:
            from src.core.concurrency_governor import get_governor

            get_governor().release(subsystem)
        except ImportError:
            logger.warning("Operation failed in capacity_manager.py", exc_info=True)
        except Exception as exc:
            logger.debug("CapacityManager: ConcurrencyGovernor release failed: %s", exc)

    def _get_in_flight_count(self) -> int:
        """Get the number of in-flight tasks across all subsystems."""
        try:
            from src.core.task_registry import get_task_registry

            return get_task_registry().active_count()
        except ImportError:
            logger.warning("Operation failed in capacity_manager.py", exc_info=True)
        except Exception:
            logger.warning("Operation failed in capacity_manager.py", exc_info=True)
        return 0

    def _record_denial(self, reason: str) -> None:
        with self._lock:
            self._denied_count += 1
            self._last_denial = reason

    def snapshot(self) -> dict[str, Any]:
        """Return diagnostic snapshot of capacity state."""
        snapshot: dict[str, Any] = {
            "reserve_ram_mb": self.reserve_ram_mb,
            "allowed_count": self._allowed_count,
            "denied_count": self._denied_count,
            "last_denial": self._last_denial,
        }

        # ResourceGuard state
        try:
            from src.infrastructure.resource_guard import ResourceGuard

            guard = ResourceGuard()
            snapshot["available_ram_mb"] = guard._get_available_ram_mb()
        except Exception:
            snapshot["available_ram_mb"] = "unavailable"

        # ConcurrencyGovernor state
        try:
            from src.core.concurrency_governor import get_governor

            snapshot["concurrency"] = get_governor().snapshot()
        except Exception:
            snapshot["concurrency"] = "unavailable"

        # TaskRegistry state
        try:
            from src.core.task_registry import get_task_registry

            snapshot["tasks"] = get_task_registry().status()
        except Exception:
            snapshot["tasks"] = "unavailable"

        return snapshot


_capacity_manager: CapacityManager | None = None
_capacity_manager_lock = threading.Lock()


def get_capacity_manager() -> CapacityManager:
    """Return the process-wide CapacityManager singleton."""
    global _capacity_manager
    with _capacity_manager_lock:
        if _capacity_manager is None:
            _capacity_manager = CapacityManager()
        return _capacity_manager


__all__ = [
    "CapacityManager",
    "get_capacity_manager",
]
