from __future__ import annotations

from src.jobs import JobEvent, JobEventType, JobStatus, MemoryJobStore, StageKey
from src.jobs.replay import replay


def test_replay_reconstructs_completed_job() -> None:
    events = [
        JobEvent(type=JobEventType.QUEUED, job_id="r1", message="q", timestamp=1),
        JobEvent(type=JobEventType.STARTED, job_id="r1", message="s", timestamp=2),
        JobEvent(
            type=JobEventType.STAGE_COMPLETED,
            job_id="r1",
            message="ok",
            stage=StageKey.SUBDOMAINS.value,
            timestamp=3,
        ),
        JobEvent(type=JobEventType.COMPLETED, job_id="r1", message="done", timestamp=4),
    ]
    job = replay(events)
    assert job["id"] == "r1"
    assert job["status"] == JobStatus.COMPLETED.value


def test_store_events_can_replay() -> None:
    store = MemoryJobStore()
    created = store.create(base_url="https://r.test")
    store.transition(created["id"], JobStatus.RUNNING)
    store.finish(created["id"], returncode=0)
    rebuilt = replay(store.events.for_job(created["id"]), base_url="https://r.test")
    assert rebuilt["status"] in {JobStatus.COMPLETED.value, JobStatus.RUNNING.value, JobStatus.STARTING.value}
