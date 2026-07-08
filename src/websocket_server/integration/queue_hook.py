"""Queue system integration — broadcasts job state transitions via WebSocket."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def integrate_with_queue_system(services: Any) -> None:
    """Hook into the queue system to broadcast job state transitions."""
    try:
        from src.infrastructure.queue.models import JobState
    except (ImportError, ModuleNotFoundError):
        logger.debug("queue.models not available; skipping queue integration")
        return

    progress_map = {
        JobState.PENDING: 0,
        JobState.RUNNING: 25,
        JobState.COMPLETED: 100,
        JobState.FAILED: 100,
        JobState.CANCELLED: 100,
        JobState.DEAD_LETTER: 100,
    }

    def _estimate_progress(job: Any) -> int:
        state = getattr(job, "state", None)
        return progress_map.get(state, 0)

    async def _on_job_state_change(job: Any, previous_state: Any) -> None:
        job_id = str(getattr(job, "id", "unknown"))
        state = getattr(job, "state", None)
        progress = _estimate_progress(job)
        status_str = str(state.value) if hasattr(state, "value") else str(state)
        try:
            services.broadcast_progress(job_id, "queue", progress, status=status_str)
            if hasattr(job, "result") and job.result:
                services.broadcast_status(job_id, status_str, detail=str(job.result)[:500])
        except Exception as exc:
            logger.debug("Queue broadcast failed for %s: %s", job_id, exc)

    try:
        from src.infrastructure.queue import get_job_queue
        queue = get_job_queue()
        if hasattr(queue, "on_state_change"):
            queue.on_state_change(_on_job_state_change)
            logger.debug("Queue system integration installed")
    except Exception as exc:
        logger.debug("Queue integration setup failed: %s", exc)
