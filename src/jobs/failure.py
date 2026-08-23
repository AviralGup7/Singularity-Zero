"""Failure taxonomy for pipeline jobs."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from src.jobs.records import mark_finished
from src.jobs.status import JobStatus, _transition, apply_pipeline_exit_status


class FailureCode(StrEnum):
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    BUDGET = "global_deadline_exceeded"
    RECON = "recon_validation"
    AUTH = "auth_failed"
    NETWORK = "network"
    RATE_LIMIT = "rate_limit"
    TOOL = "tool_failed"
    CANCELLED = "cancelled"
    CONFIG = "config"
    SANDBOX = "sandbox"


_MARKERS: tuple[tuple[FailureCode, tuple[str, ...]], ...] = (
    (
        FailureCode.BUDGET,
        ("global_deadline", "budget exceeded", "max duration", "deadline exceeded"),
    ),
    (FailureCode.TIMEOUT, ("timed out", "timeout")),
    (FailureCode.RECON, ("recon_validation", "recon failed", "no live hosts")),
    (FailureCode.AUTH, ("401", "403", "unauthorized", "forbidden")),
    (FailureCode.RATE_LIMIT, ("429", "rate limit", "retry-after")),
    (FailureCode.NETWORK, ("econnrefused", "dns", "network", "connection reset")),
    (FailureCode.SANDBOX, ("wasm", "sandbox", "isolate")),
    (FailureCode.CONFIG, ("invalid config", "missing scope")),
    (FailureCode.CANCELLED, ("stop requested", "cancelled", "canceled")),
)


@dataclass(frozen=True, slots=True)
class JobFailure:
    code: FailureCode
    stage: str
    message: str
    step: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "failure_reason_code": self.code.value,
            "failed_stage": self.stage,
            "failure_reason": self.message,
            "failure_step": self.step,
        }


def classify_failure(text: object, *, stage: str = "") -> JobFailure:
    blob = str(text or "").strip().lower()
    code = FailureCode.UNKNOWN
    for candidate, markers in _MARKERS:
        if any(marker in blob for marker in markers):
            code = candidate
            break
    message = str(text or "").strip() or code.value
    return JobFailure(code=code, stage=stage, message=message[:2000])


def apply_failure(job: dict[str, Any], failure: JobFailure) -> dict[str, Any]:
    job.update(failure.to_dict())
    job["error"] = failure.message
    _transition(job, JobStatus.FAILED)
    return mark_finished(job)


def apply_exit(
    job: dict[str, Any],
    *,
    returncode: int,
    stop_requested: bool = False,
    stderr: str = "",
    no_pipeline_output: bool = False,
) -> dict[str, Any]:
    job["returncode"] = int(returncode)
    job["stop_requested"] = bool(stop_requested)
    if stderr:
        lines = [line for line in stderr.splitlines() if line.strip()]
        job["stderr_fatal_lines"] = lines[-40:]
        job["fatal_signal_count"] = len(lines)
    apply_pipeline_exit_status(
        job,
        stop_requested=stop_requested,
        returncode=returncode,
        no_pipeline_output=no_pipeline_output,
        has_running_stages=False,
    )
    if job.get("status") == JobStatus.FAILED.value and stderr:
        apply_failure(job, classify_failure(stderr, stage=str(job.get("stage") or "")))
        return job
    return mark_finished(job)
