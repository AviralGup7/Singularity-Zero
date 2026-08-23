"""Stage progress mutations on a job record."""

from __future__ import annotations

import time
from typing import Any

from src.jobs.records import touch
from src.jobs.stages import (
    STAGE_LABELS,
    StageProgress,
    StageStatus,
    parse_stage_key,
    parse_stage_status,
    stage_band_percent,
)
from src.jobs.status import JobStatus, _transition


def _stage_map(job: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = job.get("stage_progress")
    if not isinstance(raw, dict):
        raw = {}
        job["stage_progress"] = raw
    return raw


def set_stage(
    job: dict[str, Any],
    stage: object,
    status: object,
    *,
    processed: int = 0,
    total: int | None = None,
    percent: int | None = None,
    reason: str = "",
    error: str = "",
    message: str = "",
    now: float | None = None,
) -> StageProgress:
    epoch = float(now if now is not None else time.time())
    key = parse_stage_key(stage).value
    parsed_status = parse_stage_status(status)
    inner = 0.0
    if total and total > 0:
        inner = min(max(processed / float(total), 0.0), 1.0)
    resolved_percent = percent if percent is not None else stage_band_percent(key, inner)
    payload = _stage_map(job).setdefault(key, {})
    if "started_at" not in payload:
        payload["started_at"] = epoch
    retry_count = int(payload.get("retry_count", 0) or 0)
    if parsed_status is StageStatus.RETRYING:
        retry_count += 1
    progress = StageProgress(
        stage=key,
        status=parsed_status,
        processed=int(processed),
        total=total,
        percent=int(resolved_percent),
        reason=reason,
        error=error,
        retry_count=retry_count,
        last_event=message or parsed_status.value,
        started_at=float(payload.get("started_at") or epoch),
        updated_at=epoch,
    )
    payload.update(progress.to_dict())
    job["stage"] = key
    job["stage_label"] = STAGE_LABELS.get(key, key)
    job["status_message"] = message or progress.last_event
    job["progress_percent"] = max(int(job.get("progress_percent", 0) or 0), progress.percent)
    history = job.setdefault("progress_history", [])
    if isinstance(history, list):
        history.append((epoch, job["progress_percent"]))
        if len(history) > 400:
            del history[:-400]
    telemetry = job.setdefault("progress_telemetry", {})
    if isinstance(telemetry, dict):
        transitions = telemetry.setdefault("stage_transitions", [])
        if isinstance(transitions, list):
            transitions.append(
                {
                    "stage": key,
                    "status": parsed_status.value,
                    "timestamp": epoch,
                    "message": progress.last_event,
                }
            )
        if parsed_status is StageStatus.FAILED:
            telemetry["failure_count"] = int(telemetry.get("failure_count", 0) or 0) + 1
        if parsed_status is StageStatus.RETRYING:
            telemetry["retry_count"] = int(telemetry.get("retry_count", 0) or 0) + 1
        if parsed_status is StageStatus.SKIPPED:
            skipped = telemetry.setdefault("skipped_stages", [])
            if isinstance(skipped, list) and key not in skipped:
                skipped.append(key)
        running = sum(
            1
            for item in _stage_map(job).values()
            if isinstance(item, dict)
            and parse_stage_status(item.get("status")) is StageStatus.RUNNING
        )
        telemetry["active_task_count"] = running
    if parsed_status is StageStatus.FAILED:
        job["failed_stage"] = key
        job["failure_reason"] = error or message
        _transition(job, JobStatus.FAILED)
    elif parsed_status is StageStatus.RUNNING:
        _transition(job, JobStatus.RUNNING)
    touch(job, now=epoch)
    return progress


def running_stage_count(job: dict[str, Any]) -> int:
    return sum(
        1
        for item in _stage_map(job).values()
        if isinstance(item, dict) and parse_stage_status(item.get("status")) is StageStatus.RUNNING
    )


def overall_percent(job: dict[str, Any]) -> int:
    stages = _stage_map(job)
    if not stages:
        return int(job.get("progress_percent", 0) or 0)
    percents = [
        int(item.get("percent", 0) or 0) for item in stages.values() if isinstance(item, dict)
    ]
    if not percents:
        return int(job.get("progress_percent", 0) or 0)
    return max(percents)


def apply_finding_counts(
    job: dict[str, Any],
    *,
    total: int | None = None,
    critical: int | None = None,
    high: int | None = None,
) -> None:
    if total is not None:
        job["findings_count"] = int(total)
    if critical is not None:
        job["critical_findings"] = int(critical)
    if high is not None:
        job["high_findings"] = int(high)
    touch(job)
