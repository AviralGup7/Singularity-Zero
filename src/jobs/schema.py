"""Validate job records before they hit FastAPI."""

from __future__ import annotations

from typing import Any

from src.jobs.stages import parse_stage_key
from src.jobs.status import parse_job_status

REQUIRED_KEYS = (
    "id",
    "base_url",
    "hostname",
    "status",
    "started_at",
    "updated_at",
    "stage",
    "progress_percent",
)


class JobSchemaError(ValueError):
    pass


def validate_job(job: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(job, dict):
        return ["job is not a dict"]
    for key in REQUIRED_KEYS:
        if key not in job:
            errors.append(f"missing:{key}")
    if job.get("id") in {None, ""}:
        errors.append("empty_id")
    try:
        parse_job_status(job.get("status"))
    except Exception as exc:  # pragma: no cover
        errors.append(f"status:{exc}")
    try:
        parse_stage_key(job.get("stage"))
    except Exception as exc:  # pragma: no cover
        errors.append(f"stage:{exc}")
    percent = job.get("progress_percent", 0)
    try:
        value = int(percent)
    except (TypeError, ValueError):
        errors.append("percent_nan")
    else:
        if value < 0 or value > 100:
            errors.append("percent_range")
    started = job.get("started_at")
    updated = job.get("updated_at")
    if (
        isinstance(started, (int, float))
        and isinstance(updated, (int, float))
        and updated < started
    ):
        errors.append("clock_skew")
    return errors


def require_valid(job: dict[str, Any]) -> dict[str, Any]:
    errors = validate_job(job)
    if errors:
        raise JobSchemaError(",".join(errors))
    return job
