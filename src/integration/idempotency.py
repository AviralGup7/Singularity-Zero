"""In-memory idempotency cache for mutating console commands."""

from __future__ import annotations

import threading
import time
from typing import Any


class IdempotencyCache:
    def __init__(self, *, ttl_seconds: float = 600.0, limit: int = 512) -> None:
        self._ttl = max(30.0, float(ttl_seconds))
        self._limit = max(16, int(limit))
        self._lock = threading.RLock()
        self._items: dict[str, tuple[float, dict[str, Any]]] = {}

    def _purge(self, now: float) -> None:
        expired = [key for key, (created, _) in self._items.items() if now - created > self._ttl]
        for key in expired:
            self._items.pop(key, None)
        if len(self._items) > self._limit:
            oldest = sorted(self._items.items(), key=lambda item: item[1][0])
            for key, _ in oldest[: len(self._items) - self._limit]:
                self._items.pop(key, None)

    def get(self, key: str | None) -> dict[str, Any] | None:
        if not key:
            return None
        now = time.time()
        with self._lock:
            self._purge(now)
            packed = self._items.get(key)
            return dict(packed[1]) if packed else None

    def put(self, key: str | None, payload: dict[str, Any]) -> None:
        if not key:
            return
        now = time.time()
        with self._lock:
            self._purge(now)
            self._items[key] = (now, dict(payload))

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)
