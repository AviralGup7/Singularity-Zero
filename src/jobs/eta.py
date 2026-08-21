"""ETA helpers for active jobs."""

from __future__ import annotations

from typing import Any

from src.jobs.stages import STAGE_PERCENT_BANDS, parse_stage_key
from src.jobs.status import is_active_job_status


def elapsed_seconds(job: dict[str, Any], *, now: float) -> float:
    started = float(job.get("started_at") or now)
    finished = job.get("finished_at")
    end = float(finished) if finished else now
    return max(0.0, end - started)


def remaining_seconds(job: dict[str, Any], *, now: float) -> float | None:
    if not is_active_job_status(job.get("status")):
        return 0.0
    elapsed = elapsed_seconds(job, now=now)
    percent = max(int(job.get("progress_percent", 0) or 0), 1)
    if percent >= 100:
        return 0.0
    projected = elapsed * (100.0 / percent)
    remaining = projected - elapsed
    stage = parse_stage_key(job.get("stage")).value
    start, end = STAGE_PERCENT_BANDS.get(stage, (0, 100))
    width = max(end - start, 1)
    # Widen the estimate slightly while a stage is still in its first third.
    if percent < start + width / 3:
        remaining *= 1.15
    return round(max(0.0, remaining), 1)


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    value = int(round(max(0.0, seconds)))
    hours, rem = divmod(value, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def stalled(job: dict[str, Any], *, now: float, after_seconds: float = 180.0) -> bool:
    if not is_active_job_status(job.get("status")):
        return False
    updated = float(job.get("updated_at") or job.get("started_at") or now)
    return (now - updated) >= after_seconds
