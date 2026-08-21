"""In-memory job store implementing the domain contract."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable
from typing import Any, Protocol

from src.jobs.events import EventLog, JobEvent, JobEventType, event_for_status
from src.jobs.failure import JobFailure, apply_exit, apply_failure
from src.jobs.progress import set_stage
from src.jobs.query import JobFilter, Page, counts_by_status, filter_jobs, paginate, sort_jobs
from src.jobs.records import create_job_record, touch
from src.jobs.status import JobStatus, _transition, parse_job_status


class JobStore(Protocol):
    def put(self, job: dict[str, Any]) -> dict[str, Any]: ...
    def get(self, job_id: str) -> dict[str, Any] | None: ...
    def delete(self, job_id: str) -> bool: ...
    def list(self, spec: JobFilter | None = None) -> list[dict[str, Any]]: ...


class MemoryJobStore:
    def __init__(self, *, event_limit: int = 4000) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self.events = EventLog(limit=event_limit)
        self._listeners: list[Callable[[JobEvent], None]] = []

    def subscribe(self, listener: Callable[[JobEvent], None]) -> None:
        with self._lock:
            self._listeners.append(listener)

    def _emit(self, event: JobEvent) -> JobEvent:
        self.events.append(event)
        for listener in list(self._listeners):
            listener(event)
        return event

    def put(self, job: dict[str, Any]) -> dict[str, Any]:
        job_id = str(job.get("id") or "")
        if not job_id:
            raise ValueError("job id required")
        with self._lock:
            self._jobs[job_id] = job
        self._emit(
            JobEvent(
                type=JobEventType.QUEUED,
                job_id=job_id,
                message="queued",
                stage=str(job.get("stage") or "startup"),
                status=str(job.get("status") or JobStatus.PENDING.value),
            )
        )
        return job

    def create(self, **kwargs: Any) -> dict[str, Any]:
        record = create_job_record(**kwargs)
        return self.put(record)

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job is not None else None

    def delete(self, job_id: str) -> bool:
        with self._lock:
            return self._jobs.pop(job_id, None) is not None

    def list(self, spec: JobFilter | None = None) -> list[dict[str, Any]]:
        with self._lock:
            jobs = [dict(job) for job in self._jobs.values()]
        return sort_jobs(filter_jobs(jobs, spec))

    def page(self, spec: JobFilter | None = None, *, offset: int = 0, limit: int = 50) -> Page:
        return paginate(self.list(spec), offset=offset, limit=limit)

    def counts(self) -> dict[str, int]:
        with self._lock:
            return counts_by_status(self._jobs.values())

    def transition(self, job_id: str, status: object, *, message: str = "") -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            ok = _transition(job, status)
            if not ok:
                return dict(job)
            touch(job)
            snapshot = dict(job)
        self._emit(event_for_status(job_id, snapshot["status"], message=message, stage=snapshot.get("stage")))
        return snapshot

    def update_stage(self, job_id: str, stage: object, status: object, **kwargs: Any) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            set_stage(job, stage, status, **kwargs)
            snapshot = dict(job)
        return snapshot

    def fail(self, job_id: str, failure: JobFailure) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            apply_failure(job, failure)
            snapshot = dict(job)
        self._emit(event_for_status(job_id, JobStatus.FAILED, message=failure.message, stage=failure.stage))
        return snapshot

    def finish(self, job_id: str, *, returncode: int = 0, stop_requested: bool = False, stderr: str = "") -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            apply_exit(job, returncode=returncode, stop_requested=stop_requested, stderr=stderr)
            snapshot = dict(job)
        self._emit(event_for_status(job_id, snapshot["status"], stage=snapshot.get("stage")))
        return snapshot

    def request_stop(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            job["stop_requested"] = True
            _transition(job, JobStatus.STOPPING)
            touch(job)
            snapshot = dict(job)
        self._emit(
            JobEvent(
                type=JobEventType.STOP_REQUESTED,
                job_id=job_id,
                message="stop requested",
                status=JobStatus.STOPPING.value,
                stage=str(snapshot.get("stage") or ""),
            )
        )
        return snapshot

    def heartbeat(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            touch(job)
        self._emit(
            JobEvent(
                type=JobEventType.HEARTBEAT,
                job_id=job_id,
                message="heartbeat",
                timestamp=time.time(),
            )
        )

    def __len__(self) -> int:
        with self._lock:
            return len(self._jobs)

    def ids(self) -> list[str]:
        with self._lock:
            return list(self._jobs)

    def drop_terminal(self) -> int:
        from src.jobs.status import is_terminal_job_status

        removed = 0
        with self._lock:
            for job_id, job in list(self._jobs.items()):
                if is_terminal_job_status(job.get("status")):
                    self._jobs.pop(job_id, None)
                    removed += 1
        return removed


def iter_active(store: MemoryJobStore) -> Iterable[dict[str, Any]]:
    from src.jobs.status import is_active_job_status

    for job in store.list():
        if is_active_job_status(job.get("status")):
            yield job
