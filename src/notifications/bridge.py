"""Push job domain events into the notification inbox."""

from __future__ import annotations

from src.jobs.events import JobEvent, JobEventType
from src.jobs.store import MemoryJobStore
from src.notifications.inbox import Inbox
from src.notifications.templates import job_completed, job_failed, stage_failed


def connect(store: MemoryJobStore, inbox: Inbox) -> None:
    def _on_event(event: JobEvent) -> None:
        if event.type is JobEventType.COMPLETED:
            inbox.push(
                job_completed(
                    event.job_id,
                    event.payload.get("hostname", ""),
                    int(event.payload.get("findings", 0) or 0),
                )
            )
        elif event.type is JobEventType.FAILED:
            inbox.push(
                job_failed(event.job_id, str(event.payload.get("hostname") or ""), event.message)
            )
        elif event.type is JobEventType.STAGE_FAILED:
            inbox.push(stage_failed(event.job_id, event.stage, event.message))

    store.subscribe(_on_event)
