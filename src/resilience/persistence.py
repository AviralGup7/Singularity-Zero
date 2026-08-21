"""JSON persistence for ToolCircuitBreaker snapshots."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from src.resilience.circuit_breaker import ToolCircuitBreaker


class BreakerStore:
    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()

    def save(self, breaker: ToolCircuitBreaker) -> None:
        payload = breaker.snapshot()
        text = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(text, encoding="utf-8")
            tmp.replace(self._path)

    def load(self, breaker: ToolCircuitBreaker) -> bool:
        if not self._path.is_file():
            return False
        with self._lock:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return False
        breaker.restore(raw)
        return True

    def exists(self) -> bool:
        return self._path.is_file()


class MemoryBreakerJournal:
    """Append-only journal of breaker snapshots for tests and local runs."""

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []

    def record(self, breaker: ToolCircuitBreaker, *, reason: str) -> dict[str, Any]:
        entry = {"reason": reason, "snapshot": breaker.snapshot()}
        self._entries.append(entry)
        return entry

    def last(self) -> dict[str, Any] | None:
        return self._entries[-1] if self._entries else None

    def __len__(self) -> int:
        return len(self._entries)
