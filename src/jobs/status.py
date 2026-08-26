"""Job status machine.

Independent of FastAPI and the dashboard package. Dashboard code must
import these symbols from ``src.jobs`` (the ``src.dashboard.job_status``
module is a compatibility shim).

Every writer that mutates ``job["status"]`` must go through
``_transition``. Terminal states cannot leave.

::

    PENDING → STARTING → RUNNING ⇄ STOPPING → STOPPED
                         │
                         ├── COMPLETED
                         └── FAILED

COMPLETED, FAILED, and STOPPED are terminal.
"""

from __future__ import annotations

import logging
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class JobStatus(StrEnum):
    PENDING = "pending"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


TERMINAL_JOB_STATUSES: frozenset[JobStatus] = frozenset(
    {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.STOPPED}
)

ACTIVE_JOB_STATUSES: frozenset[JobStatus] = frozenset(
    {JobStatus.PENDING, JobStatus.STARTING, JobStatus.RUNNING, JobStatus.STOPPING}
)

_ALLOWED: dict[JobStatus, frozenset[JobStatus]] = {
    JobStatus.PENDING: frozenset(
        {
            JobStatus.STARTING,
            JobStatus.RUNNING,
            JobStatus.FAILED,
            JobStatus.STOPPED,  # cancel arrived before start
        }
    ),
    JobStatus.STARTING: frozenset(
        {
            JobStatus.RUNNING,
            JobStatus.STOPPING,
            JobStatus.FAILED,
            JobStatus.STOPPED,
        }
    ),
    JobStatus.RUNNING: frozenset(
        {
            JobStatus.STOPPING,
            JobStatus.COMPLETED,
            JobStatus.FAILED,
            JobStatus.STOPPED,
        }
    ),
    JobStatus.STOPPING: frozenset({JobStatus.STOPPED, JobStatus.FAILED}),
    JobStatus.COMPLETED: frozenset(),
    JobStatus.FAILED: frozenset(),
    JobStatus.STOPPED: frozenset(),
}


def parse_job_status(value: object) -> JobStatus:
    raw = str(value or "").strip().lower()
    for status in JobStatus:
        if raw == status.value:
            return status
    if raw in {"idle", "queued", "created"}:
        return JobStatus.PENDING
    if raw in {"busy", "in_progress"}:
        return JobStatus.RUNNING
    if raw in {"error", "crashed", "interrupted"}:
        return JobStatus.FAILED
    if raw in {"cancelled", "canceled"}:
        return JobStatus.STOPPED
    return JobStatus.PENDING


def is_terminal_job_status(value: object) -> bool:
    return parse_job_status(value) in TERMINAL_JOB_STATUSES


def is_active_job_status(value: object) -> bool:
    return parse_job_status(value) in ACTIVE_JOB_STATUSES


def can_transition_job(current: object, target: object) -> bool:
    source = parse_job_status(current)
    dest = parse_job_status(target)
    if source == dest:
        return True
    return dest in _ALLOWED.get(source, frozenset())


def _transition(job: dict[str, Any], new_status: str | JobStatus) -> bool:
    """Apply ``new_status`` if the transition is legal.

    Returns True when the job now holds ``new_status`` (including a
    no-op self-transition). Terminal states never leave.
    """
    dest = parse_job_status(new_status)
    current_raw = job.get("status")
    source = parse_job_status(current_raw)
    if source == dest:
        job["status"] = dest.value
        return True
    if source in TERMINAL_JOB_STATUSES:
        logger.warning(
            "Rejected illegal job transition %s -> %s (terminal) job=%s",
            source.value,
            dest.value,
            job.get("id"),
        )
        return False
    if dest not in _ALLOWED.get(source, frozenset()):
        logger.warning(
            "Rejected illegal job transition %s -> %s job=%s",
            source.value,
            dest.value,
            job.get("id"),
        )
        return False
    job["status"] = dest.value
    return True


def apply_pipeline_exit_status(
    job: dict[str, Any],
    *,
    stop_requested: bool,
    returncode: int,
    no_pipeline_output: bool = False,
    has_running_stages: bool = False,
    stage_map: dict[str, Any] | None = None,
    findings: list[Any] | None = None,
    policy: Any | None = None,
    policy_violated: bool | None = None,
) -> bool:
    """Map a reaped pipeline process onto a legal terminal job status.

    Direct ``job["status"] =`` writes are forbidden. STOPPING cannot
    become COMPLETED — a clean stop reaps as STOPPED instead.
    When ``stage_map`` is supplied, :func:`derive_job_and_exit` is the
    single lattice; returncode is the fallback for process-only reap.
    """
    job["exit_code"] = int(returncode)
    if stop_requested:
        dest = JobStatus.STOPPED
    elif stage_map is not None:
        from src.jobs.run_outcome import derive_job_and_exit

        dest = derive_job_and_exit(
            stage_map,
            findings,
            policy,
            cancel=False,
            policy_violated=policy_violated or returncode == 2,
        ).job_status
        # Empty/placeholder stage maps must not mask a process that exited 0
        # with no stdout/stderr — that is pipeline_no_output (FAILED).
        if dest is JobStatus.COMPLETED and returncode == 0 and no_pipeline_output:
            dest = JobStatus.FAILED
        elif dest is JobStatus.COMPLETED and returncode in (1, 3):
            dest = JobStatus.FAILED
        elif dest is JobStatus.COMPLETED and returncode == 4:
            job["degraded"] = True
        elif dest is JobStatus.COMPLETED and returncode in (130, 7):
            dest = JobStatus.STOPPED
    elif returncode == 0 and (no_pipeline_output or has_running_stages):
        dest = JobStatus.FAILED
    elif returncode in (0, 2):
        dest = JobStatus.COMPLETED
    elif returncode == 4:
        job["degraded"] = True
        dest = JobStatus.COMPLETED
    elif returncode in (130, 7):
        dest = JobStatus.STOPPED
    elif returncode in (1, 3):
        dest = JobStatus.FAILED
    else:
        dest = JobStatus.FAILED
    if _transition(job, dest):
        return True
    if dest is JobStatus.COMPLETED:
        return _transition(job, JobStatus.STOPPED)
    return False
