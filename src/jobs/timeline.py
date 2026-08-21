"""Build a linear timeline from stage_progress + events."""

from __future__ import annotations

from typing import Any

from src.jobs.events import EventLog, JobEvent
from src.jobs.stages import STAGE_ORDER, StageKey, parse_stage_status


def stage_timeline(job: dict[str, Any]) -> list[dict[str, Any]]:
    progress = job.get("stage_progress") if isinstance(job.get("stage_progress"), dict) else {}
    rows: list[dict[str, Any]] = []
    for key in STAGE_ORDER:
        payload = progress.get(key.value) if isinstance(progress, dict) else None
        if not isinstance(payload, dict):
            rows.append(
                {
                    "stage": key.value,
                    "status": "pending" if key is not StageKey.COMPLETED else "pending",
                    "percent": 0,
                }
            )
            continue
        rows.append(
            {
                "stage": key.value,
                "status": parse_stage_status(payload.get("status")).value,
                "percent": int(payload.get("percent", 0) or 0),
                "processed": payload.get("processed", 0),
                "total": payload.get("total"),
                "error": payload.get("error", ""),
                "retry_count": payload.get("retry_count", 0),
            }
        )
    return rows


def event_timeline(log: EventLog, job_id: str) -> list[dict[str, Any]]:
    return [event.to_dict() for event in log.for_job(job_id)]


def merge_timelines(job: dict[str, Any], log: EventLog) -> dict[str, Any]:
    return {
        "job_id": str(job.get("id") or ""),
        "status": job.get("status"),
        "stages": stage_timeline(job),
        "events": event_timeline(log, str(job.get("id") or "")),
    }
