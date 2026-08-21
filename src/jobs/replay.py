"""Replay recorded job events onto a fresh record."""

from __future__ import annotations

from typing import Any

from src.jobs.events import JobEvent, JobEventType
from src.jobs.progress import set_stage
from src.jobs.records import create_job_record, touch
from src.jobs.stages import StageStatus
from src.jobs.status import JobStatus, _transition


def replay(events: list[JobEvent], *, base_url: str = "https://replay.test") -> dict[str, Any]:
    if not events:
        return create_job_record(base_url=base_url)
    job_id = events[0].job_id
    job = create_job_record(job_id=job_id, base_url=base_url, now=events[0].timestamp)
    for event in events:
        if event.type is JobEventType.STARTED:
            _transition(job, JobStatus.RUNNING)
        elif event.type is JobEventType.STAGE_STARTED:
            set_stage(job, event.stage, StageStatus.RUNNING, now=event.timestamp)
        elif event.type is JobEventType.STAGE_COMPLETED:
            set_stage(job, event.stage, StageStatus.COMPLETED, now=event.timestamp)
        elif event.type is JobEventType.STAGE_FAILED:
            set_stage(job, event.stage, StageStatus.FAILED, error=event.message, now=event.timestamp)
        elif event.type is JobEventType.STAGE_SKIPPED:
            set_stage(job, event.stage, StageStatus.SKIPPED, reason=event.message, now=event.timestamp)
        elif event.type is JobEventType.COMPLETED:
            _transition(job, JobStatus.COMPLETED)
        elif event.type is JobEventType.FAILED:
            _transition(job, JobStatus.FAILED)
            job["error"] = event.message
        elif event.type is JobEventType.STOPPED:
            _transition(job, JobStatus.STOPPED)
        elif event.type is JobEventType.STOP_REQUESTED:
            job["stop_requested"] = True
            _transition(job, JobStatus.STOPPING)
        touch(job, now=event.timestamp)
    return job
