from __future__ import annotations

from src.jobs import JobStatus, MemoryJobStore
from src.jobs.batch import health, stop_all_running
from src.jobs.metrics import JobMetrics
from src.jobs.simulator import PipelineSimulator


def test_metrics_and_batch_stop() -> None:
    store = MemoryJobStore()
    sim = PipelineSimulator(store)
    sim.run(base_url="https://ok.test", findings=2)
    running = store.create(base_url="https://run.test")
    store.transition(running["id"], JobStatus.RUNNING)
    stopped = stop_all_running(store)
    assert stopped >= 1
    metrics = JobMetrics()
    metrics.observe(store)
    payload = metrics.to_dict()
    assert payload["created"] >= 2
    snap = health(store, now=running["started_at"] + 1)
    assert snap["total"] >= 2
