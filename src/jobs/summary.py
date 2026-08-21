"""Operator-facing job summary derived from the domain record."""

from __future__ import annotations

from typing import Any

from src.jobs.eta import elapsed_seconds, format_duration, remaining_seconds, stalled
from src.jobs.progress import overall_percent, running_stage_count
from src.jobs.status import parse_job_status
from src.jobs.stages import parse_stage_key


def summarize(job: dict[str, Any], *, now: float) -> dict[str, Any]:
    status = parse_job_status(job.get("status"))
    stage = parse_stage_key(job.get("stage"))
    elapsed = elapsed_seconds(job, now=now)
    remaining = remaining_seconds(job, now=now)
    return {
        "id": job.get("id"),
        "hostname": job.get("hostname"),
        "mode": job.get("mode"),
        "status": status.value,
        "stage": stage.value,
        "progress_percent": overall_percent(job),
        "running_stages": running_stage_count(job),
        "elapsed_label": format_duration(elapsed),
        "eta_label": format_duration(remaining),
        "stalled": stalled(job, now=now),
        "findings_count": int(job.get("findings_count", 0) or 0),
        "critical_findings": int(job.get("critical_findings", 0) or 0),
        "error": job.get("error") or "",
        "failed_stage": job.get("failed_stage") or "",
    }


def summarize_many(jobs: list[dict[str, Any]], *, now: float) -> list[dict[str, Any]]:
    return [summarize(job, now=now) for job in jobs]


def health_from_jobs(jobs: list[dict[str, Any]], *, now: float) -> dict[str, Any]:
    summaries = summarize_many(jobs, now=now)
    stalled_ids = [row["id"] for row in summaries if row["stalled"]]
    failed = [row["id"] for row in summaries if row["status"] == "failed"]
    running = [row["id"] for row in summaries if row["status"] in {"running", "starting"}]
    return {
        "total": len(summaries),
        "running": len(running),
        "failed": len(failed),
        "stalled": stalled_ids,
        "ok": not stalled_ids and not failed,
    }
