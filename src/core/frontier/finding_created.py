"""Type-enforced FINDING_CREATED payload (I31). Cannot be built without wal_id."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class FindingCreated:
    """Authoritative finding event. Constructor refuses missing I31 bindings."""

    wal_id: str
    settlement_id: str
    event_id: str
    finding: dict[str, Any]

    def __post_init__(self) -> None:
        if not str(self.wal_id or "").strip():
            raise ValueError("FINDING_CREATED requires wal_id")
        if not str(self.settlement_id or "").strip():
            raise ValueError("FINDING_CREATED requires settlement_id")
        if not str(self.event_id or "").strip():
            raise ValueError("FINDING_CREATED requires event_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "wal_id": self.wal_id,
            "settlement_id": self.settlement_id,
            "event_id": self.event_id,
            "finding": dict(self.finding),
        }


__all__ = ["FindingCreated"]
