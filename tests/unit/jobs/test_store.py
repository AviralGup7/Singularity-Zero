from __future__ import annotations

from src.jobs import (
    FailureCode,
    JobFilter,
    JobStatus,
    MemoryJobStore,
    StageStatus,
    classify_failure,
)


def test_create_transition_and_finish() -> None:
    store = MemoryJobStore()
    job = store.create(base_url="https://app.example.com", mode_name="idor")
    job_id = job["id"]
    assert job["status"] == JobStatus.STARTING.value
    running = store.transition(job_id, JobStatus.RUNNING)
    assert running["status"] == JobStatus.RUNNING.value
    store.update_stage(job_id, "active_scan", StageStatus.RUNNING, processed=3, total=10)
    finished = store.finish(job_id, returncode=0)
    assert finished["status"] == JobStatus.COMPLETED.value
    assert finished["finished_at"] is not None
    assert store.counts()[JobStatus.COMPLETED.value] == 1


def test_stop_request_and_filter() -> None:
    store = MemoryJobStore()
    job = store.create(base_url="https://api.example.com", hostname="api.example.com")
    store.transition(job["id"], JobStatus.RUNNING)
    stopping = store.request_stop(job["id"])
    assert stopping["status"] == JobStatus.STOPPING.value
    store.finish(job["id"], returncode=0, stop_requested=True)
    active = store.list(JobFilter(active_only=True))
    terminal = store.list(JobFilter(terminal_only=True))
    assert active == []
    assert len(terminal) == 1


def test_fail_classifies_timeout() -> None:
    failure = classify_failure("tool timed out after 30s", stage="nuclei")
    assert failure.code is FailureCode.TIMEOUT
    store = MemoryJobStore()
    job = store.create(base_url="https://x.test")
    store.transition(job["id"], JobStatus.RUNNING)
    failed = store.fail(job["id"], failure)
    assert failed["status"] == JobStatus.FAILED.value
    assert failed["failed_stage"] == "nuclei"


def test_unknown_job_raises() -> None:
    store = MemoryJobStore()
    try:
        store.get("missing")
        store.transition("missing", JobStatus.RUNNING)
    except KeyError:
        pass
    else:
        # get returns None; transition must raise
        raised = False
        try:
            store.transition("missing", JobStatus.RUNNING)
        except KeyError:
            raised = True
        assert raised
