"""Analyst feedback loop records."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum


class FeedbackLabel(StrEnum):
    TRUE_POSITIVE = "tp"
    FALSE_POSITIVE = "fp"
    DUPLICATE = "dup"
    NEEDS_REVIEW = "review"


@dataclass(slots=True)
class Feedback:
    finding_id: str
    label: FeedbackLabel
    analyst: str
    note: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "label": self.label.value,
            "analyst": self.analyst,
            "note": self.note,
            "timestamp": self.timestamp,
        }


class FeedbackBook:
    def __init__(self) -> None:
        self._items: list[Feedback] = []

    def add(self, item: Feedback) -> Feedback:
        self._items.append(item)
        return item

    def for_finding(self, finding_id: str) -> list[Feedback]:
        return [item for item in self._items if item.finding_id == finding_id]

    def latest_label(self, finding_id: str) -> FeedbackLabel | None:
        rows = self.for_finding(finding_id)
        return rows[-1].label if rows else None

    def fp_rate(self) -> float:
        if not self._items:
            return 0.0
        fp = sum(1 for item in self._items if item.label is FeedbackLabel.FALSE_POSITIVE)
        return round(fp / len(self._items), 3)

    def __len__(self) -> int:
        return len(self._items)
