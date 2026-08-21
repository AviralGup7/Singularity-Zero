"""Detect stalled jobs and request stops."""

from __future__ import annotations

from dataclasses import dataclass

from src.jobs.eta import stalled
from src.jobs.status import JobStatus, is_active_job_status  # JobStatus used in force_fail
from src.jobs.store import MemoryJobStore


@dataclass(frozen=True, slots=True)
class WatchdogReport:
    checked: int
    stalled: tuple[str, ...]
    stopped: tuple[str, ...]


class JobWatchdog:
    def __init__(self, store: MemoryJobStore, *, after_seconds: float = 300.0, auto_stop: bool = False) -> None:
        self.store = store
        self.after_seconds = after_seconds
        self.auto_stop = auto_stop

    def tick(self, *, now: float) -> WatchdogReport:
        stalled_ids: list[str] = []
        stopped_ids: list[str] = []
        checked = 0
        for job in self.store.list():
            if not is_active_job_status(job.get("status")):
                continue
            checked += 1
            if not stalled(job, now=now, after_seconds=self.after_seconds):
                continue
            job_id = str(job["id"])
            stalled_ids.append(job_id)
            if self.auto_stop:
                self.store.request_stop(job_id)
                self.store.finish(job_id, returncode=1, stop_requested=True, stderr="watchdog stalled")
                stopped_ids.append(job_id)
        return WatchdogReport(checked=checked, stalled=tuple(stalled_ids), stopped=tuple(stopped_ids))

    def force_fail(self, job_id: str, message: str) -> None:
        job = self.store.get(job_id)
        if job is None:
            return
        if job.get("status") == JobStatus.FAILED.value:
            return
        from src.jobs.failure import FailureCode, JobFailure

        self.store.fail(job_id, JobFailure(FailureCode.TIMEOUT, str(job.get("stage") or ""), message))
