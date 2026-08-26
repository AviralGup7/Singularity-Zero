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
    assert job["exit_code"] == 3


def test_derive_job_and_exit_total_precedence() -> None:
    from src.jobs.run_outcome import (
        EXIT_INFRA_FAILURE,
        EXIT_INTERRUPTED,
        EXIT_OK,
        EXIT_PARTIAL,
        EXIT_POLICY_VIOLATION,
        derive_job_and_exit,
    )

    # 1. Cancel wins over everything (130)
    outcome = derive_job_and_exit(
        {"subdomains": "FAILED"},
        [{"finding": 1}],
        cancel=True,
        policy_violated=True,
    )
    assert outcome.exit_code == EXIT_INTERRUPTED
    assert outcome.job_status == JobStatus.STOPPED

    # 2. Fatal stage / infra failure wins over policy violation (3 > 2)
    outcome = derive_job_and_exit(
        {"subdomains": "FAILED", "reporting": "COMPLETED"},
        [{"finding": 1}],
        policy_violated=True,
        fatal_stages=("subdomains",),
    )
    assert outcome.exit_code == EXIT_INFRA_FAILURE
    assert outcome.job_status == JobStatus.FAILED

    # 3. Policy violation wins over degraded (2 > 4)
    outcome = derive_job_and_exit(
        {"subdomains": "DEGRADED", "reporting": "COMPLETED"},
        [{"finding": 1}],
        policy_violated=True,
    )
    assert outcome.exit_code == EXIT_POLICY_VIOLATION
    assert outcome.job_status == JobStatus.COMPLETED

    # 4. Degraded wins over clean (4 > 0)
    outcome = derive_job_and_exit(
        {"subdomains": "DEGRADED", "reporting": "COMPLETED"},
        [],
        policy_violated=False,
    )
    assert outcome.exit_code == EXIT_PARTIAL
    assert outcome.job_status == JobStatus.COMPLETED

    # 5. Clean run (0)
    outcome = derive_job_and_exit(
        {"subdomains": "COMPLETED", "reporting": "COMPLETED"},
        [],
        policy_violated=False,
    )
    assert outcome.exit_code == EXIT_OK
    assert outcome.job_status == JobStatus.COMPLETED


def test_derive_job_and_exit_no_pipeline_output() -> None:
    from src.jobs.run_outcome import EXIT_INFRA_FAILURE, derive_job_and_exit

    outcome = derive_job_and_exit(
        {"subdomains": "COMPLETED"},
        [],
        no_pipeline_output=True,
    )
    assert outcome.exit_code == EXIT_INFRA_FAILURE
    assert outcome.job_status == JobStatus.FAILED
    assert outcome.reason == "pipeline_no_output"
