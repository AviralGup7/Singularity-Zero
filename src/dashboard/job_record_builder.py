"""Job record builder utility for creating initial pipeline job tracking structures."""

import time
from typing import Any

from src.core.telemetry import build_telemetry_event
from src.dashboard.registry import STAGE_LABELS


def create_job_record(
    job_id: str,
    normalized_url: str,
    hostname: str,
    scope_entries: list[str],
    enabled_modules: list[str],
    target_name: str,
    mode_name: str,
    execution_options: dict[str, bool] | None = None,
) -> dict[str, Any]:
    """Create a new job record for tracking a pipeline run.

    Args:
        job_id: Unique job identifier.
        normalized_url: Target base URL.
        hostname: Target hostname.
        scope_entries: List of scope entries.
        enabled_modules: List of enabled module names.
        target_name: Target name for output directory.
        mode_name: Pipeline mode (e.g., 'idor', 'ssrf').
        execution_options: Optional execution flags.

    Returns:
        Job record dict with initial state and metadata.
    """
    started_at = time.time()
    flags = execution_options or {}
    startup_event = build_telemetry_event(
        event_type="pipeline.queued",
        stage="startup",
        message="Run queued",
        status="running",
        source="dashboard.launcher",
        trace_id=job_id,
        target=target_name,
        run_id=job_id,
        epoch=started_at,
        payload={"base_url": normalized_url, "mode": mode_name, "modules": enabled_modules},
    )
    return {
        "id": job_id,
        "base_url": normalized_url,
        "hostname": hostname,
        "scope_entries": scope_entries,
        "enabled_modules": enabled_modules,
        "mode": mode_name,
        "target_name": target_name,
        "status": "running",
        "started_at": started_at,
        "updated_at": started_at,
        "finished_at": None,
        "stage": "startup",
        "stage_label": STAGE_LABELS["startup"],
        "status_message": "Creating config and scope",
        "progress_percent": 2,
        "stage_processed": None,
        "stage_total": None,
        "progress_history": [(started_at, 2)],
        "progress_telemetry": {
            "active_task_count": 1,
            "retry_count": 0,
            "failure_count": 0,
            "targets": {"queued": 0, "scanning": 0, "done": 0},
            "stage_transitions": [
                {
                    "stage": "startup",
                    "status": "running",
                    "timestamp": started_at,
                    "message": "Creating config and scope",
                }
            ],
            "event_triggers": [],
            "skipped_stages": [],
            "top_active_targets": [],
            "event_counts": {"pipeline.queued": 1},
            "artifact_counts": {},
            "last_update_epoch": started_at,
        },
        "telemetry_events": [startup_event],
        "config_href": f"/_launcher/{job_id}/config.json",
        "scope_href": f"/_launcher/{job_id}/scope.txt",
        "stdout_href": f"/_launcher/{job_id}/stdout.txt",
        "stderr_href": f"/_launcher/{job_id}/stderr.txt",
        "target_href": f"/{target_name}/index.html",
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
            f"Scope: {', '.join(scope_entries)}",
            f"Modules: {', '.join(enabled_modules) or 'none'}",
        ],
    }
