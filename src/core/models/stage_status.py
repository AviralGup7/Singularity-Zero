"""CAS-style pipeline stage status machine.

Illegal transitions keep the existing status instead of overwriting:

    COMPLETED → FAILED     rejected
    COMPLETED → SKIPPED*   rejected
    FAILED → COMPLETED     rejected
    SKIPPED* → COMPLETED   rejected

``SKIPPED`` is split so a failed stage cannot satisfy downstream gates:

    SKIPPED_DISABLED  — stage was not configured / not applicable
    SKIPPED_FAILED    — stage was skipped because it failed (circuit, error)
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class StageStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"  # legacy alias; stored as SKIPPED_DISABLED
    SKIPPED_DISABLED = "SKIPPED_DISABLED"
    SKIPPED_FAILED = "SKIPPED_FAILED"


TERMINAL_STAGE_STATUSES: frozenset[StageStatus] = frozenset(
    {
        StageStatus.COMPLETED,
        StageStatus.FAILED,
        StageStatus.SKIPPED_DISABLED,
        StageStatus.SKIPPED_FAILED,
        StageStatus.DEGRADED,
    }
)

_FAILED_SKIP_REASONS = frozenset(
    {
        "circuit_breaker_open",
        "failed",
        "error",
        "timeout",
        "stage_failed",
        "retries_exhausted",
        "max retries exhausted",
    }
)


def normalize_stage_status(value: object) -> StageStatus:
    raw = str(value or "").strip().upper()
    aliases = {
        "": StageStatus.PENDING,
        "PENDING": StageStatus.PENDING,
        "RUNNING": StageStatus.RUNNING,
        "COMPLETED": StageStatus.COMPLETED,
        "DONE": StageStatus.COMPLETED,
        "SUCCESS": StageStatus.COMPLETED,
        "DEGRADED": StageStatus.DEGRADED,
        "FAILED": StageStatus.FAILED,
        "ERROR": StageStatus.FAILED,
        "TIMEOUT": StageStatus.FAILED,
        "SKIPPED": StageStatus.SKIPPED_DISABLED,
        "SKIP": StageStatus.SKIPPED_DISABLED,
        "SKIPPED_DISABLED": StageStatus.SKIPPED_DISABLED,
        "SKIPPED_FAILED": StageStatus.SKIPPED_FAILED,
    }
    if raw in aliases:
        return aliases[raw]
    try:
        return StageStatus(raw)
    except ValueError:
        return StageStatus.PENDING


def is_skipped_status(value: object) -> bool:
    return normalize_stage_status(value) in {
        StageStatus.SKIPPED,
        StageStatus.SKIPPED_DISABLED,
        StageStatus.SKIPPED_FAILED,
    }


def skipped_satisfies_gate(value: object) -> bool:
    """True only for intentional/disabled skips, never for failed skips."""
    return normalize_stage_status(value) in {
        StageStatus.SKIPPED_DISABLED,
        StageStatus.SKIPPED,
    }


def is_failed_skip_reason(reason: object) -> bool:
    text = str(reason or "").strip().lower()
    if not text:
        return False
    if text in _FAILED_SKIP_REASONS:
        return True
    return any(token in text for token in ("fail", "error", "timeout", "circuit"))


_ALLOWED: dict[StageStatus, frozenset[StageStatus]] = {
    StageStatus.PENDING: frozenset(
        {
            StageStatus.RUNNING,
            StageStatus.COMPLETED,
            StageStatus.DEGRADED,
            StageStatus.FAILED,
            StageStatus.SKIPPED_DISABLED,
            StageStatus.SKIPPED_FAILED,
        }
    ),
    StageStatus.RUNNING: frozenset(
        {
            StageStatus.COMPLETED,
            StageStatus.DEGRADED,
            StageStatus.FAILED,
            StageStatus.SKIPPED_DISABLED,
            StageStatus.SKIPPED_FAILED,
        }
    ),
    StageStatus.DEGRADED: frozenset(),
    StageStatus.COMPLETED: frozenset(),
    StageStatus.FAILED: frozenset(),
    StageStatus.SKIPPED: frozenset(),
    StageStatus.SKIPPED_DISABLED: frozenset(),
    StageStatus.SKIPPED_FAILED: frozenset(),
}


def transition_stage_status(current: object, target: object) -> str:
    """Return the status that should be stored after a CAS attempt."""
    source = normalize_stage_status(current)
    dest = normalize_stage_status(target)
    if source == dest:
        return source.value
    if dest not in _ALLOWED.get(source, frozenset()):
        logger.debug(
            "Rejected illegal stage transition %s -> %s; keeping %s",
            source.value,
            dest.value,
            source.value,
        )
        return source.value
    return dest.value


def resolve_skip_status(reason: object = "") -> StageStatus:
    if is_failed_skip_reason(reason):
        return StageStatus.SKIPPED_FAILED
    return StageStatus.SKIPPED_DISABLED


class StageStatusMap(dict[str, str]):
    """Dict that applies CAS rules on every write."""

    def __init__(self, data: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None) -> None:
        super().__init__()
        if data:
            pairs: Iterable[tuple[Any, Any]] = data.items() if isinstance(data, Mapping) else data
            for key, value in pairs:
                super().__setitem__(str(key), transition_stage_status(StageStatus.PENDING, value))

    def __setitem__(self, key: str, value: object) -> None:
        current = super().get(key, StageStatus.PENDING.value)
        super().__setitem__(str(key), transition_stage_status(current, value))

    def update(self, *args: Any, **kwargs: Any) -> None:  # type: ignore[override]
        incoming: dict[str, Any] = {}
        if args:
            other = args[0]
            if isinstance(other, Mapping):
                incoming.update(other)
            else:
                incoming.update(dict(other))
        incoming.update(kwargs)
        for key, value in incoming.items():
            self[key] = value
