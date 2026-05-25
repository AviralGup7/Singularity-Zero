"""Job snapshotting and serialization logic."""

import time
from datetime import UTC, datetime
from typing import Any

from src.dashboard.job_state_helpers import (
    STALLED_AFTER_SECONDS,
    _coerce_epoch,
    _compute_eta_bayesian,
    _compute_eta_fallback,
    _normalize_stage_status,
    _stage_progress_label,
)
from src.dashboard.registry import STAGE_LABELS
from src.dashboard.utils import format_duration, format_epoch_ist


def _snapshot_progress_telemetry(
    job: dict[str, Any],
    *,
    now: float,
) -> dict[str, Any]:
    from src.dashboard.progress_ingestion import _ensure_progress_telemetry, _stage_running_count

    telemetry = _ensure_progress_telemetry(job)
    stage_progress = job.get("stage_progress")
    running_stages: list[tuple[str, dict[str, Any], float]] = []
    if isinstance(stage_progress, dict):
        for stage_name, payload in stage_progress.items():
            if not isinstance(payload, dict):
                continue
            status = _normalize_stage_status(payload.get("status"))
            if status != "running":
                continue
            started = _coerce_epoch(payload.get("started_at"), now)
            running_stages.append((stage_name, payload, started))

    if running_stages:
        bottleneck_stage, _, bottleneck_started = max(
            running_stages,
            key=lambda item: now - item[2],
        )
        telemetry.setdefault("bottleneck_stage", bottleneck_stage)
        telemetry.setdefault("bottleneck_seconds", round(max(0.0, now - bottleneck_started), 1))

    telemetry["active_task_count"] = max(
        int(telemetry.get("active_task_count", 0) or 0),
        _stage_running_count(job),
    )
    telemetry["last_update_epoch"] = _coerce_epoch(job.get("updated_at"), now)

    return dict(telemetry)


def snapshot_job(job: dict[str, Any]) -> dict[str, Any]:
    now = time.time()
    started_at = _coerce_epoch(job.get("started_at"), now)
    updated_at = _coerce_epoch(job.get("updated_at"), started_at)
    finished_at_raw = job.get("finished_at")
    finished_at = _coerce_epoch(finished_at_raw, 0.0) if finished_at_raw else None
    elapsed_seconds = (finished_at or now) - started_at

    status = str(job.get("status", "unknown"))
    stage = str(job.get("stage", "startup"))
    progress_percent = int(job.get("progress_percent", 0) or 0)

    if status == "running":
        from src.dashboard.fastapi.config import FeatureFlags

        if FeatureFlags.ENABLE_BAYESIAN_ETA():
            remaining_seconds = _compute_eta_bayesian(job, elapsed_seconds)
        else:
            remaining_seconds = _compute_eta_fallback(job, elapsed_seconds)
    else:
        remaining_seconds = 0

    since_update = now - updated_at
    stalled = status == "running" and since_update >= STALLED_AFTER_SECONDS
    stage_progress_label = _stage_progress_label(job)

    # Build ordered list of stage progress entries for the API response
    raw_stage_progress = job.get("stage_progress", {})

    # Handle legacy data where stage_progress was already serialized as a list
    if isinstance(raw_stage_progress, list):
        stage_progress_list = raw_stage_progress
    else:
        stage_order_list = [
            "startup",
            "subdomains",
            "live_hosts",
            "urls",
            "parameters",
            "ranking",
            "priority",
            "passive_scan",
            "active_scan",
            "nuclei",
            "access_control",
            "validation",
            "intelligence",
            "reporting",
            "completed",
        ]
        stage_progress_list = []
        for skey in stage_order_list:
            if skey in raw_stage_progress:
                sp = raw_stage_progress[skey]
                stage_progress_list.append(
                    {
                        "stage": sp.get("stage", skey),
                        "stage_label": sp.get(
                            "stage_label", STAGE_LABELS.get(skey, skey.replace("_", " ").title())
                        ),
                        "status": _normalize_stage_status(sp.get("status", "running")),
                        "processed": sp.get("processed", 0),
                        "total": sp.get("total"),
                        "percent": sp.get("percent", 0),
                        "reason": sp.get("reason", ""),
                        "error": sp.get("error", ""),
                        "retry_count": sp.get("retry_count", 0),
                        "last_event": sp.get("last_event", ""),
                        "started_at": sp.get("started_at"),
                        "updated_at": sp.get("updated_at"),
                    }
                )
        # Include any stages not in the predefined order
        for skey, sp in raw_stage_progress.items():
            if skey not in {s["stage"] for s in stage_progress_list}:
                stage_progress_list.append(
                    {
                        "stage": sp.get("stage", skey),
                        "stage_label": sp.get(
                            "stage_label", STAGE_LABELS.get(skey, skey.replace("_", " ").title())
                        ),
                        "status": _normalize_stage_status(sp.get("status", "running")),
                        "processed": sp.get("processed", 0),
                        "total": sp.get("total"),
                        "percent": sp.get("percent", 0),
                        "reason": sp.get("reason", ""),
                        "error": sp.get("error", ""),
                        "retry_count": sp.get("retry_count", 0),
                        "last_event": sp.get("last_event", ""),
                        "started_at": sp.get("started_at"),
                        "updated_at": sp.get("updated_at"),
                    }
                )

    telemetry_events = job.get("telemetry_events")
    if not isinstance(telemetry_events, list):
        telemetry_events = []

    return {
        "id": str(job.get("id", "")),
        "base_url": str(job.get("base_url", "")),
        "hostname": str(job.get("hostname", "")),
        "scope_entries": list(job.get("scope_entries", [])),
        "enabled_modules": list(job.get("enabled_modules", [])),
        "mode": job.get("mode", "idor"),
        "target_name": str(job.get("target_name", "")),
        "status": status,
        "started_at": datetime.fromtimestamp(started_at, tz=UTC).isoformat(),
        "updated_at": datetime.fromtimestamp(updated_at, tz=UTC).isoformat(),
        "finished_at": (
            datetime.fromtimestamp(finished_at, tz=UTC).isoformat()
            if finished_at is not None
            else None
        ),
        "started_at_label": format_epoch_ist(started_at),
        "updated_at_label": format_epoch_ist(updated_at),
        "finished_at_label": format_epoch_ist(finished_at),
        "stage": stage,
        "stage_label": str(
            job.get("stage_label", STAGE_LABELS.get(stage, stage.replace("_", " ").title()))
        ),
        "status_message": str(job.get("status_message", "")),
        "failed_stage": str(job.get("failed_stage", "")),
        "failure_reason_code": str(job.get("failure_reason_code", "")),
        "failure_step": str(job.get("failure_step", "")),
        "failure_reason": str(job.get("failure_reason", "")),
        "progress_percent": progress_percent,
        "returncode": job.get("returncode"),
        "error": str(job.get("error", "")),
        "warnings": list(job.get("warnings", [])),
        "warning_count": int(job.get("warning_count", len(job.get("warnings", [])) or 0) or 0),
        "stderr_warning_lines": list(job.get("stderr_warning_lines", [])),
        "stderr_fatal_lines": list(job.get("stderr_fatal_lines", [])),
        "fatal_signal_count": int(job.get("fatal_signal_count", 0) or 0),
        "timeout_events": list(job.get("timeout_events", [])),
        "degraded_providers": list(job.get("degraded_providers", [])),
        "configured_timeout_seconds": job.get("configured_timeout_seconds"),
        "effective_timeout_seconds": job.get("effective_timeout_seconds"),
        "execution_options": dict(job.get("execution_options", {})),
        "can_stop": status == "running",
        "latest_logs": list(job.get("latest_logs", [])),
        "config_href": str(job.get("config_href", "")),
        "scope_href": str(job.get("scope_href", "")),
        "stdout_href": str(job.get("stdout_href", "")),
        "stderr_href": str(job.get("stderr_href", "")),
        "target_href": str(job.get("target_href", "")),
        "elapsed_seconds": round(elapsed_seconds, 1),
        "elapsed_label": format_duration(elapsed_seconds),
        "eta_label": format_duration(remaining_seconds),
        "has_eta": remaining_seconds is not None,
        "last_update_label": format_duration(since_update),
        "stalled": stalled,
        "stage_progress_label": stage_progress_label,
        "stage_progress": stage_progress_list,
        "progress_telemetry": _snapshot_progress_telemetry(job, now=now),
        "telemetry_events": telemetry_events[-500:],
        # Expose the count of concurrently running stages for the frontend
        "concurrent_stage_count": len(
            [
                s
                for s in (
                    raw_stage_progress.values() if isinstance(raw_stage_progress, dict) else []
                )
                if isinstance(s, dict) and s.get("status") == "running"
            ]
        ),
        "state_version": int(job.get("state_version", 0) or 0),
    }
