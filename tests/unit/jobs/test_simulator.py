from __future__ import annotations

from src.jobs import JobStatus, MemoryJobStore
from src.jobs.simulator import PipelineSimulator


def test_simulator_completes() -> None:
    sim = PipelineSimulator()
    job_id = sim.run(base_url="https://sim.test", findings=4)
    job = sim.store.get(job_id)
    assert job is not None
    assert job["status"] == JobStatus.COMPLETED.value
    assert job["findings_count"] == 4


def test_simulator_can_fail_mid_pipeline() -> None:
    store = MemoryJobStore()
    sim = PipelineSimulator(store)
    job_id = sim.run(base_url="https://sim.test", fail_at="nuclei")
    job = store.get(job_id)
    assert job is not None
    assert job["status"] == JobStatus.FAILED.value
    assert job["failed_stage"] == "nuclei"
