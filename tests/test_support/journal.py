"""In-memory WAL mock for unit & integration testing."""

from __future__ import annotations

from typing import Any

from src.frontier.deltas import apply_many, snapshot_counts
from src.frontier.verify import replay_gap


class MemoryJournal:
    """Mock WAL implementation strictly intended for test harnesses."""

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []

    def append(self, payload: dict[str, Any]) -> str:
        wal_id = str(payload.get("_wal_id") or f"{len(self._entries) + 1}-0")
        payload = dict(payload)
        payload["_wal_id"] = wal_id
        self._entries.append(payload)
        return wal_id

    def since(self, cursor: str | None) -> list[dict[str, Any]]:
        if not cursor:
            return list(self._entries)
        skip = replay_gap(cursor, [str(item.get("_wal_id")) for item in self._entries])
        skip_set = set(skip)
        return [item for item in self._entries if str(item.get("_wal_id")) not in skip_set]

    def replay(self, cursor: str | None = None) -> dict[str, int]:
        state = apply_many(self.since(cursor))
        return snapshot_counts(state)

    def __len__(self) -> int:
        return len(self._entries)

