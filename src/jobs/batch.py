"""Batch helpers over MemoryJobStore."""

from __future__ import annotations

from src.jobs.query import JobFilter
from src.jobs.status import JobStatus
from src.jobs.store import MemoryJobStore
from src.jobs.summary import health_from_jobs


def stop_all_running(store: MemoryJobStore) -> int:
    stopped = 0
    for job in store.list(JobFilter(active_only=True)):
        if job.get("status") in {
            JobStatus.RUNNING.value,
            JobStatus.STARTING.value,
            JobStatus.PENDING.value,
        }:
            store.request_stop(str(job["id"]))
            store.finish(str(job["id"]), returncode=0, stop_requested=True)
            stopped += 1
    return stopped


def health(store: MemoryJobStore, *, now: float) -> dict[str, object]:
    return health_from_jobs(store.list(), now=now)
