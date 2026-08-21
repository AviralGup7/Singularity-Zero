from __future__ import annotations

from src.jobs.history import JobHistory
from src.jobs.simulator import PipelineSimulator
from src.jobs.store import MemoryJobStore


def test_history_ingests_finished_jobs() -> None:
    store = MemoryJobStore()
    PipelineSimulator(store).run(base_url="https://h.test", findings=3)
    history = JobHistory()
    history.ingest(store)
    assert history.findings_total() == 3
    assert history.to_dict()["count"] == 1
