from __future__ import annotations

from src.jobs import JobStatus, MemoryJobStore
from src.jobs.summary import health_from_jobs, summarize
from src.jobs.watchdog import JobWatchdog


def test_watchdog_flags_stalled_job() -> None:
    store = MemoryJobStore()
    job = store.create(base_url="https://app.test", now=1.0)
    store.transition(job["id"], JobStatus.RUNNING)
    current = store.get(job["id"])
    assert current is not None
    current["updated_at"] = 1.0
    store.put(current)
    report = JobWatchdog(store, after_seconds=50, auto_stop=True).tick(now=200.0)
    assert job["id"] in report.stalled or report.checked >= 1


def test_summary_health() -> None:
    store = MemoryJobStore()
    job = store.create(base_url="https://app.test")
    snapshot = summarize(job, now=job["started_at"] + 5)
    assert snapshot["status"] == JobStatus.STARTING.value
    health = health_from_jobs([job], now=job["started_at"] + 5)
    assert health["total"] == 1
