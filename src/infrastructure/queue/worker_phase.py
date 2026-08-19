"""Worker lifecycle phases for fault-tolerant dispatch.

::

    REGISTERING
         ↓
       READY
         ↓
      RUNNING  ←── heartbeat ──┐
         │                     │
         ├── graceful stop → DRAINING → DEAD
         │
         └── heartbeat timeout → SUSPECT
                                      │
                                 confirmation
                                      ↓
                                    DEAD
                                      ↓
                              task reassignment
"""

from __future__ import annotations

from enum import StrEnum


class WorkerPhase(StrEnum):
    """Canonical worker lifecycle. Legacy status strings map through aliases."""

    REGISTERING = "registering"
    READY = "ready"
    RUNNING = "running"
    DRAINING = "draining"
    SUSPECT = "suspect"
    DEAD = "dead"


_ALIASES: dict[str, WorkerPhase] = {
    "idle": WorkerPhase.READY,
    "busy": WorkerPhase.RUNNING,
    "shutting_down": WorkerPhase.DRAINING,
    "starting": WorkerPhase.REGISTERING,
}


def normalize_phase(value: str | WorkerPhase | None) -> WorkerPhase:
    """Accept new phases and the older idle/busy/shutting_down labels."""
    if isinstance(value, WorkerPhase):
        return value
    raw = str(value or "").strip().lower()
    if not raw:
        return WorkerPhase.READY
    aliased = _ALIASES.get(raw)
    if aliased is not None:
        return aliased
    try:
        return WorkerPhase(raw)
    except ValueError:
        return WorkerPhase.READY


def legacy_status(phase: WorkerPhase) -> str:
    """Map a phase to the WorkerInfo.status strings existing tests still read."""
    return {
        WorkerPhase.REGISTERING: "idle",
        WorkerPhase.READY: "idle",
        WorkerPhase.RUNNING: "busy",
        WorkerPhase.DRAINING: "shutting_down",
        WorkerPhase.SUSPECT: "suspect",
        WorkerPhase.DEAD: "dead",
    }[phase]
