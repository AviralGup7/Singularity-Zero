"""Append-only Event Store and deterministic state projection engine (CQRS)."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from src.core.events.events import DomainEvent


class EventStore:
    """Append-only ledger of domain events with deterministic replay."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[DomainEvent] = []

    def append(self, event: DomainEvent) -> None:
        with self._lock:
            self._events.append(event)

    def append_batch(self, events: list[DomainEvent]) -> None:
        with self._lock:
            self._events.extend(events)

    def get_all(self) -> list[DomainEvent]:
        with self._lock:
            return list(self._events)

    def count(self) -> int:
        with self._lock:
            return len(self._events)

    def filter_by_type(self, event_type: str) -> list[DomainEvent]:
        with self._lock:
            return [e for e in self._events if e.event_type == event_type]

    def project(self, initial_state: Any, reducer: Callable[[Any, DomainEvent], Any]) -> Any:
        """Reconstruct state deterministically by replaying all historical events."""
        state = initial_state
        with self._lock:
            for ev in self._events:
                state = reducer(state, ev)
        return state


__all__ = ["EventStore"]
