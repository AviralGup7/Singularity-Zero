"""Job record factory that does not import the dashboard package."""

from __future__ import annotations

import time
import uuid
from typing import Any

from src.jobs.stages import STAGE_LABELS, StageKey
from src.jobs.status import JobStatus


def new_job_id() -> str:
    return uuid.uuid4().hex[:12]


def create_job_record(
    *,
    job_id: str | None = None,
    base_url: str,
    hostname: str = "",
    scope_entries: list[str] | None = None,
    enabled_modules: list[str] | None = None,
    target_name: str = "",
    mode_name: str = "standard",
    execution_options: dict[str, bool] | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    started_at = float(now if now is not None else time.time())
    resolved_id = job_id or new_job_id()
    host = hostname or _hostname_from_url(base_url)
    target = target_name or host or resolved_id
    flags = execution_options or {}
    modules = list(enabled_modules or [])
    scope = list(scope_entries or [base_url])
    return {
        "id": resolved_id,
        "base_url": base_url,
        "hostname": host,
        "scope_entries": scope,
        "enabled_modules": modules,
        "mode": mode_name,
        "target_name": target,
        "status": JobStatus.STARTING.value,
        "started_at": started_at,
        "updated_at": started_at,
        "finished_at": None,
        "stage": StageKey.STARTUP.value,
        "stage_label": STAGE_LABELS[StageKey.STARTUP.value],
        "status_message": "Creating config and scope",
        "progress_percent": 2,
        "stage_processed": None,
        "stage_total": None,
        "progress_history": [(started_at, 2)],
        "stage_progress": {},
        "progress_telemetry": {
            "active_task_count": 1,
            "retry_count": 0,
            "failure_count": 0,
            "targets": {"queued": 0, "scanning": 0, "done": 0},
            "stage_transitions": [
                {
                    "stage": StageKey.STARTUP.value,
                    "status": "running",
                    "timestamp": started_at,
                    "message": "Creating config and scope",
                }
            ],
            "event_triggers": [],
            "skipped_stages": [],
            "top_active_targets": [],
            "event_counts": {"job.queued": 1},
            "artifact_counts": {},
            "last_update_epoch": started_at,
        },
        "telemetry_events": [],
        "config_href": f"/_launcher/{resolved_id}/config.json",
        "scope_href": f"/_launcher/{resolved_id}/scope.txt",
        "stdout_href": f"/_launcher/{resolved_id}/stdout.txt",
        "stderr_href": f"/_launcher/{resolved_id}/stderr.txt",
        "target_href": f"/{target}/index.html",
        "returncode": None,
        "error": "",
        "failed_stage": "",
        "failure_reason_code": "",
        "failure_step": "",
        "failure_reason": "",
        "warnings": [],
        "stderr_warning_lines": [],
        "stderr_fatal_lines": [],
        "timeout_events": [],
        "degraded_providers": [],
        "configured_timeout_seconds": None,
        "effective_timeout_seconds": None,
        "warning_count": 0,
        "fatal_signal_count": 0,
        "execution_options": {
            "refresh_cache": bool(flags.get("refresh_cache")),
            "skip_crtsh": bool(flags.get("skip_crtsh")),
            "dry_run": bool(flags.get("dry_run")),
        },
        "process": None,
        "stop_requested": False,
        "latest_logs": [
            "Run queued",
            f"Mode: {mode_name}",
            f"Scope: {', '.join(scope)}",
            f"Modules: {', '.join(modules) or 'none'}",
        ],
        "state_version": 1,
        "findings_count": 0,
        "critical_findings": 0,
        "high_findings": 0,
    }


def _hostname_from_url(url: str) -> str:
    raw = str(url or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    raw = raw.split("@")[-1]
    return raw.split(":")[0]


def touch(job: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
    epoch = float(now if now is not None else time.time())
    job["updated_at"] = epoch
    job["state_version"] = int(job.get("state_version", 0) or 0) + 1
    telemetry = job.get("progress_telemetry")
    if isinstance(telemetry, dict):
        telemetry["last_update_epoch"] = epoch
    return job


def mark_finished(job: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
    epoch = float(now if now is not None else time.time())
    job["finished_at"] = epoch
    return touch(job, now=epoch)
