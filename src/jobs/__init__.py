"""Job lifecycle domain. Independent of FastAPI."""

from src.jobs.status import (
    ACTIVE_JOB_STATUSES,
    TERMINAL_JOB_STATUSES,
    JobStatus,
    apply_pipeline_exit_status,
    can_transition_job,
    is_active_job_status,
    is_terminal_job_status,
    parse_job_status,
)

__all__ = [
    "ACTIVE_JOB_STATUSES",
    "TERMINAL_JOB_STATUSES",
    "JobStatus",
    "apply_pipeline_exit_status",
    "can_transition_job",
    "is_active_job_status",
    "is_terminal_job_status",
    "parse_job_status",
]
