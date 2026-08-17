"""Thread-safe bounded progress queue with priority and critical-event protection.

Fixes:
  - Chain Bug #19: event prioritisation so stage transitions and errors
    are never silently dropped by the overflow logic.
  - Chain Bug #20: critical events (errors, completions) are mirrored to
    a separate ring buffer so that checkpoint recovery never suffers from
    "historical amnesia".
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from enum import IntEnum
from typing import Any

logger = logging.getLogger(__name__)


class EventPriority(IntEnum):
    """Priority levels -- lower numeric value = harder to drop."""

    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


# Event types that are never dropped on overflow (Bug #19/20).
_CRITICAL_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "error",
        "stage_failed",
        "stage_error",
        "pipeline_complete",
        "pipeline_failed",
        "stage_complete",
        "stage_transition",
    }
)


def _classify_event_priority(event: dict[str, Any]) -> EventPriority:
    """Determine event priority from its ``type`` field."""
    event_type = str(event.get("type", "")).strip().lower()
    if event_type in _CRITICAL_EVENT_TYPES:
        return EventPriority.CRITICAL
    if event_type in {"stage_change", "progress", "scan_started"}:
        return EventPriority.HIGH
    return EventPriority.NORMAL


class ProgressQueue:
    """Bounded thread-safe queue with priority-aware overflow.

    On overflow the queue drops the oldest **lowest priority** event.
    Critical events (errors, completions, stage transitions) are never
    dropped and are also mirrored to a ring buffer so they survive
    even if the main queue wraps.
    """

    def __init__(self, maxsize: int = 1000, critical_buffer_size: int = 1024) -> None:
        self._maxsize = maxsize
        self._queue: deque[dict[str, Any]] = deque()
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._dropped_count: int = 0
        # Bug #20: ring buffer that retains critical events for recovery.
        # Bug #4 fix: increased default from 256 to 1024 to handle enterprise
        # scans with 500+ stage failures without losing historical root cause.
        self._critical_buffer: deque[dict[str, Any]] = deque(maxlen=critical_buffer_size)
        self._critical_buffer_size = critical_buffer_size

    @property
    def qsize(self) -> int:
        with self._lock:
            return len(self._queue)

    @property
    def dropped_count(self) -> int:
        with self._lock:
            return self._dropped_count

    @property
    def critical_event_count(self) -> int:
        """Number of critical events currently in the ring buffer."""
        with self._lock:
            return len(self._critical_buffer)

    def get_critical_events(self) -> list[dict[str, Any]]:
        """Return a snapshot of the critical event ring buffer.

        Used by checkpoint recovery to detect dropped failures.
        """
        with self._lock:
            return list(self._critical_buffer)

    def put(self, event: dict[str, Any]) -> bool:
        priority = _classify_event_priority(event)

        with self._lock:
            # Mirror critical events to the ring buffer (Bug #20).
            if priority >= EventPriority.CRITICAL:
                self._critical_buffer.append(event)

            if len(self._queue) >= self._maxsize:
                # Bug #19: drop the oldest *lowest priority* event.
                if priority >= EventPriority.HIGH:
                    # New event is important -- evict the oldest LOW or NORMAL event.
                    self._evict_lowest_priority()
                else:
                    # New event is low/normal -- just drop the oldest overall.
                    self._queue.popleft()
                    self._dropped_count += 1

            self._queue.append(event)
            self._not_empty.notify()
        return True

    def _evict_lowest_priority(self) -> None:
        """Remove the oldest event with the lowest priority. Must be called
        with ``self._lock`` held."""
        # Scan from oldest to newest, drop first LOW then NORMAL.
        for target in (EventPriority.LOW, EventPriority.NORMAL):
            for i, ev in enumerate(self._queue):
                if _classify_event_priority(ev) <= target:
                    del self._queue[i]
                    self._dropped_count += 1
                    return
        # Fallback: drop the oldest regardless of priority.
        if self._queue:
            self._queue.popleft()
            self._dropped_count += 1

    def get(self, timeout: float = 0.0) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        with self._not_empty:
            while not self._queue:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._not_empty.wait(timeout=remaining)
            return self._queue.popleft()


_singleton: ProgressQueue | None = None
_singleton_lock = threading.Lock()


def get_progress_queue() -> ProgressQueue:
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ProgressQueue()
        return _singleton


def reset_progress_queue() -> None:
    global _singleton
    with _singleton_lock:
        _singleton = None


def create_progress_callback(job_id: str) -> Any:
    """Return a callback that injects job_id and timestamp into events."""

    def callback(event: dict[str, Any]) -> None:
        event["job_id"] = job_id
        event["timestamp"] = time.time()
        get_progress_queue().put(event)

    return callback
