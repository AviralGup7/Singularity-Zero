"""Job lifecycle domain. Independent of FastAPI."""

from src.jobs.eta import elapsed_seconds, format_duration, remaining_seconds, stalled
from src.jobs.events import EventLog, JobEvent, JobEventType, event_for_status, stage_event
from src.jobs.failure import FailureCode, JobFailure, apply_exit, apply_failure, classify_failure
from src.jobs.progress import apply_finding_counts, overall_percent, running_stage_count, set_stage
from src.jobs.query import JobFilter, Page, counts_by_status, filter_jobs, paginate, sort_jobs
from src.jobs.records import create_job_record, new_job_id, touch
from src.jobs.stages import STAGE_LABELS, STAGE_ORDER, StageKey, StageProgress, StageStatus
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
from src.jobs.store import MemoryJobStore
from src.jobs.timeline import merge_timelines, stage_timeline

__all__ = [
    "ACTIVE_JOB_STATUSES",
    "EventLog",
    "FailureCode",
    "JobEvent",
    "JobEventType",
    "JobFailure",
    "JobFilter",
    "JobStatus",
    "MemoryJobStore",
    "Page",
    "STAGE_LABELS",
    "STAGE_ORDER",
    "StageKey",
    "StageProgress",
    "StageStatus",
    "TERMINAL_JOB_STATUSES",
    "apply_exit",
    "apply_failure",
    "apply_finding_counts",
    "apply_pipeline_exit_status",
    "can_transition_job",
    "classify_failure",
    "counts_by_status",
    "create_job_record",
    "elapsed_seconds",
    "event_for_status",
    "filter_jobs",
    "format_duration",
    "is_active_job_status",
    "is_terminal_job_status",
    "merge_timelines",
    "new_job_id",
    "overall_percent",
    "paginate",
    "parse_job_status",
    "remaining_seconds",
    "running_stage_count",
    "set_stage",
    "sort_jobs",
    "stage_event",
    "stage_timeline",
    "stalled",
    "touch",
]
