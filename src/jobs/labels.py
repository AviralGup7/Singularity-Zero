"""Human labels for job progress and finding load."""

from __future__ import annotations

from src.jobs.status import JobStatus, parse_job_status


def status_tone(status: object) -> str:
    parsed = parse_job_status(status)
    if parsed is JobStatus.FAILED:
        return "bad"
    if parsed is JobStatus.COMPLETED:
        return "ok"
    if parsed is JobStatus.STOPPED:
        return "warn"
    if parsed is JobStatus.RUNNING:
        return "live"
    return "idle"


def findings_tone(count: int, *, critical: int = 0) -> str:
    if critical:
        return "bad"
    if count >= 20:
        return "warn"
    if count:
        return "info"
    return "ok"


def progress_label(percent: int) -> str:
    value = max(0, min(100, int(percent)))
    if value >= 100:
        return "done"
    if value >= 75:
        return "late"
    if value >= 40:
        return "mid"
    if value > 0:
        return "early"
    return "queued"
