"""Job domain events. Independent of FastAPI SSE framing."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from src.jobs.status import JobStatus, parse_job_status
from src.jobs.stages import StageKey, parse_stage_key


class JobEventType(StrEnum):
    QUEUED = "job.queued"
    STARTED = "job.started"
    STAGE_STARTED = "job.stage_started"
    STAGE_PROGRESS = "job.stage_progress"
    STAGE_COMPLETED = "job.stage_completed"
    STAGE_FAILED = "job.stage_failed"
    STAGE_SKIPPED = "job.stage_skipped"
    WARNING = "job.warning"
    LOG = "job.log"
    ARTIFACT = "job.artifact"
    HEARTBEAT = "job.heartbeat"
    STOP_REQUESTED = "job.stop_requested"
    COMPLETED = "job.completed"
    FAILED = "job.failed"
    STOPPED = "job.stopped"


_STATUS_TO_EVENT = {
    JobStatus.STARTING: JobEventType.STARTED,
    JobStatus.COMPLETED: JobEventType.COMPLETED,
    JobStatus.FAILED: JobEventType.FAILED,
    JobStatus.STOPPED: JobEventType.STOPPED,
}


@dataclass(slots=True)
class JobEvent:
    type: JobEventType
    job_id: str
    message: str
    stage: str = StageKey.STARTUP.value
    status: str = JobStatus.RUNNING.value
    timestamp: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.event_id,
            "type": self.type.value,
            "job_id": self.job_id,
            "message": self.message,
            "stage": self.stage,
            "status": self.status,
            "timestamp": self.timestamp,
            "payload": dict(self.payload),
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> JobEvent:
        raw_type = str(data.get("type") or JobEventType.LOG.value)
        try:
            event_type = JobEventType(raw_type)
        except ValueError:
            event_type = JobEventType.LOG
        return cls(
            type=event_type,
            job_id=str(data.get("job_id") or data.get("id") or ""),
            message=str(data.get("message") or ""),
            stage=parse_stage_key(data.get("stage")).value,
            status=parse_job_status(data.get("status")).value,
            timestamp=float(data.get("timestamp") or time.time()),
            event_id=str(data.get("event_id") or data.get("id") or uuid.uuid4().hex),
            payload=dict(data.get("payload") or {}),
        )


def event_for_status(job_id: str, status: object, *, message: str = "", stage: object = "startup") -> JobEvent:
    parsed = parse_job_status(status)
    event_type = _STATUS_TO_EVENT.get(parsed, JobEventType.HEARTBEAT)
    return JobEvent(
        type=event_type,
        job_id=job_id,
        message=message or parsed.value,
        stage=parse_stage_key(stage).value,
        status=parsed.value,
    )


def stage_event(
    job_id: str,
    stage: object,
    *,
    failed: bool = False,
    skipped: bool = False,
    progress: bool = False,
    message: str = "",
    processed: int = 0,
    total: int | None = None,
) -> JobEvent:
    stage_key = parse_stage_key(stage).value
    if failed:
        event_type = JobEventType.STAGE_FAILED
    elif skipped:
        event_type = JobEventType.STAGE_SKIPPED
    elif progress:
        event_type = JobEventType.STAGE_PROGRESS
    else:
        event_type = JobEventType.STAGE_COMPLETED
    return JobEvent(
        type=event_type,
        job_id=job_id,
        message=message or event_type.value,
        stage=stage_key,
        payload={"processed": processed, "total": total},
    )


class EventLog:
    """Bounded in-process log used by the memory job store and tests."""

    def __init__(self, *, limit: int = 2000) -> None:
        self._limit = max(32, int(limit))
        self._items: list[JobEvent] = []

    def append(self, event: JobEvent) -> JobEvent:
        self._items.append(event)
        if len(self._items) > self._limit:
            self._items = self._items[-self._limit :]
        return event

    def for_job(self, job_id: str) -> list[JobEvent]:
        return [event for event in self._items if event.job_id == job_id]

    def of_type(self, event_type: JobEventType) -> list[JobEvent]:
        return [event for event in self._items if event.type is event_type]

    def latest(self, job_id: str) -> JobEvent | None:
        for event in reversed(self._items):
            if event.job_id == job_id:
                return event
        return None

    def __len__(self) -> int:
        return len(self._items)

    def clear(self) -> None:
        self._items.clear()
