from __future__ import annotations

from src.jobs import (
    JobStatus,
    apply_pipeline_exit_status,
    can_transition_job,
    is_terminal_job_status,
    parse_job_status,
)
from src.jobs.status import _transition


def test_aliases_normalize() -> None:
    assert parse_job_status("queued") is JobStatus.PENDING
    assert parse_job_status("in_progress") is JobStatus.RUNNING
    assert parse_job_status("cancelled") is JobStatus.STOPPED


def test_terminal_cannot_leave() -> None:
    job = {"id": "j1", "status": JobStatus.COMPLETED.value}
    assert _transition(job, JobStatus.RUNNING) is False
    assert job["status"] == JobStatus.COMPLETED.value


def test_running_to_completed_is_legal() -> None:
    assert can_transition_job("running", "completed") is True
    assert is_terminal_job_status("completed") is True


def test_stop_requested_reaps_as_stopped() -> None:
    job = {"id": "j2", "status": JobStatus.STOPPING.value}
    assert apply_pipeline_exit_status(job, stop_requested=True, returncode=0) is True
    assert job["status"] == JobStatus.STOPPED.value


def test_lattice_policy_exit_completes_job() -> None:
    job = {"id": "j3", "status": JobStatus.RUNNING.value}
    assert (
        apply_pipeline_exit_status(
            job,
            stop_requested=False,
            returncode=2,
            stage_map={"reporting": "COMPLETED"},
            policy_violated=True,
        )
        is True
    )
    assert job["status"] == JobStatus.COMPLETED.value
    assert job["exit_code"] == 2


def test_lattice_does_not_hide_infra_exit() -> None:
    job = {"id": "j4", "status": JobStatus.RUNNING.value}
    assert (
        apply_pipeline_exit_status(
            job,
            stop_requested=False,
            returncode=3,
            stage_map={"startup": "completed"},
        )
        is True
    )
    assert job["status"] == JobStatus.FAILED.value
