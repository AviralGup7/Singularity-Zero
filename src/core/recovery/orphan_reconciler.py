"""Explainable orphan classification for outbox-without-FSM (F-018).

PRE_COMMIT orphans are ignored with evidence. CROSS_EPOCH / UNKNOWN never
auto-delete; they require --force or SURVIVAL_READONLY + human review.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class OrphanClass(StrEnum):
    PRE_COMMIT = "PRE_COMMIT"
    CROSS_EPOCH = "CROSS_EPOCH"
    STALE_EVENT = "STALE_EVENT"
    UNKNOWN = "UNKNOWN"


class OrphanAction(StrEnum):
    IGNORE = "IGNORE"
    REVIEW = "REVIEW"


@dataclass
class OrphanRecord:
    event_id: str
    orphan_class: OrphanClass
    action: OrphanAction
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "orphan_class": self.orphan_class.value,
            "action": self.action.value,
            "evidence": dict(self.evidence),
        }


def classify_orphan(
    *,
    event_id: str,
    event_commit_index: int | None = None,
    fsm_commit_index: int | None = None,
    event_epoch: int | None = None,
    live_epoch: int | None = None,
    generation: int | None = None,
    live_generation: int | None = None,
) -> OrphanRecord:
    evidence: dict[str, Any] = {
        "event_id": event_id,
        "event_commit_index": event_commit_index,
        "fsm_commit_index": fsm_commit_index,
        "event_epoch": event_epoch,
        "live_epoch": live_epoch,
        "generation": generation,
        "live_generation": live_generation,
    }
    if event_commit_index is not None and fsm_commit_index is not None:
        if event_commit_index > fsm_commit_index:
            return OrphanRecord(event_id, OrphanClass.PRE_COMMIT, OrphanAction.IGNORE, evidence)
    if event_epoch is not None and live_epoch is not None and event_epoch != live_epoch:
        return OrphanRecord(event_id, OrphanClass.CROSS_EPOCH, OrphanAction.REVIEW, evidence)
    if generation is not None and live_generation is not None and generation != live_generation:
        return OrphanRecord(event_id, OrphanClass.STALE_EVENT, OrphanAction.REVIEW, evidence)
    return OrphanRecord(event_id, OrphanClass.UNKNOWN, OrphanAction.REVIEW, evidence)


def reconcile_orphans(
    rows: list[dict[str, Any]],
    *,
    fsm_commit_index: int = 0,
    live_epoch: int = 1,
    live_generation: int = 1,
    force: bool = False,
) -> dict[str, Any]:
    classified: list[OrphanRecord] = []
    blocked = False
    for raw in rows:
        rec = classify_orphan(
            event_id=str(raw.get("event_id") or ""),
            event_commit_index=raw.get("commit_index"),
            fsm_commit_index=fsm_commit_index,
            event_epoch=raw.get("epoch"),
            live_epoch=live_epoch,
            generation=raw.get("generation"),
            live_generation=live_generation,
        )
        classified.append(rec)
        if rec.action is OrphanAction.REVIEW and not force:
            blocked = True
            logger.warning(
                "orphan requires review event_id=%s class=%s", rec.event_id, rec.orphan_class.value
            )
    return {
        "orphans": [r.to_dict() for r in classified],
        "blocked": blocked,
        "force": force,
    }


__all__ = [
    "OrphanAction",
    "OrphanClass",
    "OrphanRecord",
    "classify_orphan",
    "reconcile_orphans",
]
