from __future__ import annotations

from src.jobs import JobStatus, MemoryJobStore, filter_jobs
from src.jobs.filters_ext import failed, running
from src.jobs.simulator import PipelineSimulator


def test_failed_preset() -> None:
    store = MemoryJobStore()
    PipelineSimulator(store).run(base_url="https://ok.test")
    PipelineSimulator(store).run(base_url="https://bad.test", fail_at="nuclei")
    rows = filter_jobs(store.list(), failed())
    assert rows
    assert all(job["status"] == JobStatus.FAILED.value for job in rows)
    assert filter_jobs(store.list(), running()) == []
