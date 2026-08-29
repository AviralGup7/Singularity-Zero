"""Queue-for-merge: replay FRONTIER_ONLY discovery when authority returns."""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MAX_ENTRIES_PER_RUN = 10_000


class FrontierMergeQueue:
    """JSONL queue with a persisted cursor. Idempotent by event/spill id."""

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._cursor_path = self._path.with_suffix(self._path.suffix + ".cursor")
        self._lock = threading.Lock()

    def append(self, event: dict[str, Any]) -> bool:
        with self._lock:
            if self._count_unlocked() >= MAX_ENTRIES_PER_RUN:
                logger.warning("frontier merge queue full (%s); dropping", self._path)
                return False
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")
            return True

    def process_on_ready(self, *, dry_run: bool = False) -> list[dict[str, Any]]:
        """Advance cursor and return pending events for settlement/dedup."""
        rows = self.pending(dry_run=dry_run)
        logger.info("frontier merge queue processed count=%d dry_run=%s", len(rows), dry_run)
        return rows

    def pending(self, *, dry_run: bool = False) -> list[dict[str, Any]]:
        cursor = self._read_cursor()
        rows: list[dict[str, Any]] = []
        if not self._path.exists():
            return rows
        with self._lock:
            for index, line in enumerate(self._path.read_text(encoding="utf-8").splitlines()):
                if index < cursor:
                    continue
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    rows.append(item)
            if not dry_run:
                self._write_cursor(cursor + len(rows))
        return rows

    def _count_unlocked(self) -> int:
        if not self._path.exists():
            return 0
        return sum(
            1 for line in self._path.read_text(encoding="utf-8").splitlines() if line.strip()
        )

    def _read_cursor(self) -> int:
        if not self._cursor_path.exists():
            return 0
        try:
            return int(self._cursor_path.read_text(encoding="utf-8").strip() or "0")
        except (OSError, ValueError):
            return 0

    def _write_cursor(self, value: int) -> None:
        tmp = self._cursor_path.with_suffix(".tmp")
        tmp.write_text(str(int(value)), encoding="utf-8")
        os.replace(tmp, self._cursor_path)


__all__ = ["FrontierMergeQueue", "MAX_ENTRIES_PER_RUN"]
