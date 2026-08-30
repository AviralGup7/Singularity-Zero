"""Tiny in-memory WAL stand-in for unit tests.

NOTE: MemoryJournal has been moved to `tests.test_support.journal.MemoryJournal`.
Importing it from `src.frontier.journal` is deprecated to prevent test mocks in production.
"""

from __future__ import annotations

import os
import warnings
from typing import Any

warnings.warn(
    "Importing MemoryJournal from src.frontier.journal is deprecated. Use tests.test_support.journal.MemoryJournal instead.",
    DeprecationWarning,
    stacklevel=2,
)

from src.frontier.deltas import apply_many, snapshot_counts
from src.frontier.verify import replay_gap


class MemoryJournal:
    def __init__(self) -> None:
        env = os.environ.get("APP_ENV", "").strip().lower()
        if env in {"production", "prod", "staging"}:
            raise RuntimeError(
                f"MemoryJournal is test-only and cannot be constructed when APP_ENV={env!r}"
            )
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
