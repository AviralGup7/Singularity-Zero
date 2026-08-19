"""Per-job notification system for SSE streaming.

Replaces per-client polling loops with event-driven notifications.
Each job gets an asyncio.Event that is set whenever the job state
changes, allowing SSE streams to wait efficiently instead of polling.
"""

from __future__ import annotations

import asyncio
import logging
import time

logger = logging.getLogger(__name__)

# Per-job event: maps job_id -> Event
_job_events: dict[str, asyncio.Event] = {}
# Per-job last notification timestamp for staleness detection
_job_last_notify: dict[str, float] = {}
# Lock for thread-safe access to the event dict
_lock = asyncio.Lock()

# Maximum seconds a stream can wait before forcing a check (heartbeat fallback)
MAX_WAIT_SECONDS = 5.0


async def notify_job_updated(job_id: str) -> None:
    """Notify all SSE streams waiting on this job that state changed."""
    async with _lock:
        event = _job_events.get(job_id)
        if event is not None:
            event.set()
        _job_last_notify[job_id] = time.time()


async def wait_for_job_update(job_id: str, timeout: float = MAX_WAIT_SECONDS) -> bool:
    """Wait for a job state change notification, with timeout fallback.

    Returns True if notified, False if timed out.
    """
    async with _lock:
        if job_id not in _job_events:
            _job_events[job_id] = asyncio.Event()
        event = _job_events[job_id]
        # Clear under the same lock that notify_job_updated takes so a
        # concurrent set() cannot be wiped before wait() starts.
        event.clear()
    try:
        await asyncio.wait_for(event.wait(), timeout=timeout)
        return True
    except TimeoutError:
        return False


def register_job(job_id: str) -> None:
    """Register a job for notifications (called when job starts)."""
    if job_id not in _job_events:
        _job_events[job_id] = asyncio.Event()


def deregister_job(job_id: str) -> None:
    """Remove a job from notifications (called when job reaches terminal state)."""
    _job_events.pop(job_id, None)
    _job_last_notify.pop(job_id, None)
