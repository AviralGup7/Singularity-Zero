import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from src.core.utils.stderr_classification import (
    classify_stderr_lines,
    extract_degraded_providers,
)
from src.dashboard.job_state import _coerce_epoch
from src.dashboard.services.query_service_log_parsing import (
    last_entered_stage_from_file,
    last_progress_payload_from_file,
    normalize_progress_status,
    read_all_lines,
    tail_lines,
)


def stage_entry_status(entry: dict[str, Any] | None) -> str:
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("status", "")).strip().lower()


def is_terminal_reporting_state(
    job: dict[str, Any],
    *,
    stage_labels: dict[str, str],
) -> bool:
    stage_progress = job.get("stage_progress")
    completed_status = ""
    reporting_status = ""
    reporting_percent = 0

    if isinstance(stage_progress, dict):
        completed_status = stage_entry_status(stage_progress.get("completed"))
        reporting_entry = stage_progress.get("reporting")
        reporting_status = stage_entry_status(reporting_entry)
        if isinstance(reporting_entry, dict):
            try:
                reporting_percent = int(reporting_entry.get("percent", 0) or 0)
            except (TypeError, ValueError):
                reporting_percent = 0
    elif isinstance(stage_progress, list):
        for entry in stage_progress:
            if not isinstance(entry, dict):
                continue
            stage_name = str(entry.get("stage", "")).strip().lower()
            if stage_name == "completed":
                completed_status = stage_entry_status(entry)
            elif stage_name == "reporting":
                reporting_status = stage_entry_status(entry)
                try:
                    reporting_percent = int(entry.get("percent", 0) or 0)
                except (TypeError, ValueError):
                    reporting_percent = 0

    latest_logs = [
        str(line or "").strip() for line in job.get("latest_logs", []) if str(line or "").strip()
    ]
    has_artifact_markers = any("Artifacts written to:" in line for line in latest_logs)
    has_report_marker = any("Run report:" in line for line in latest_logs)
    has_finalizing_marker = any("Finalizing run" in line for line in latest_logs)
    has_dedup_marker = any("Deduplicated findings:" in line for line in latest_logs)

    completed_marker = completed_status in {"completed", "success", "done"}
    reporting_done = (
        reporting_status in {"completed", "success", "done"} or reporting_percent >= 100
    )

    return (
        completed_marker
        or (reporting_done and has_dedup_marker)
        or ((has_artifact_markers or has_report_marker) and has_finalizing_marker)
    )


def mark_running_stage_entries_completed(
    job: dict[str, Any],
    now: float,
    *,
    stage_labels: dict[str, str],
) -> None:
    stage_progress = job.get("stage_progress")
    if not isinstance(stage_progress, dict):
        return
    for stage_name, entry in stage_progress.items():
        if not isinstance(entry, dict):
            continue
        status = stage_entry_status(entry)
        if status == "running" and stage_name != "completed":
            entry["status"] = "completed"
            entry["updated_at"] = now
            if int(entry.get("percent", 0) or 0) < 100:
                entry["percent"] = 100

    completed_entry = stage_progress.get("completed")
    if not isinstance(completed_entry, dict):
        stage_progress["completed"] = {
            "stage": "completed",
            "stage_label": stage_labels.get("completed", "Completed"),
            "status": "completed",
            "processed": 0,
            "total": None,
            "percent": 100,
            "reason": "",
            "error": "",
            "retry_count": 0,
            "last_event": "Run complete",
            "started_at": now,
            "updated_at": now,
        }
    else:
        completed_entry["status"] = "completed"
        completed_entry["percent"] = 100
        completed_entry["last_event"] = completed_entry.get("last_event") or "Run complete"
        completed_entry["updated_at"] = now


def _truncate_lines(lines: list[str], *, limit: int = 10) -> list[str]:
    deduped: list[str] = []
    for line in lines:
        text = str(line or "").strip()
        if not text or text in deduped:
            continue
        deduped.append(text)
    return deduped[-limit:]


def recover_job_from_launcher(
    *,
    output_root: Path,
    job_id: str,
    stage_labels: dict[str, str],
    progress_prefix: str,
    path_to_output_href: Callable[[str], str],
) -> dict[str, Any] | None:
    launcher_dir = output_root / "_launcher" / job_id
    if not launcher_dir.exists() or not launcher_dir.is_dir():
        return None

    config_path = launcher_dir / "config.json"
    scope_path = launcher_dir / "scope.txt"
    stdout_path = launcher_dir / "stdout.txt"
    stderr_path = launcher_dir / "stderr.txt"
    stop_marker_path = launcher_dir / "stop_requested.marker"

    config: dict[str, Any] = {}
    try:
        parsed = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
        if isinstance(parsed, dict):
            config = parsed
    except (json.JSONDecodeError, OSError):
        config = {}

    scope_entries: list[str] = []
    try:
        if scope_path.exists():
            scope_entries = [
                line.strip()
                for line in scope_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
    except OSError:
        scope_entries = []

    stdout_lines = tail_lines(stdout_path, limit=120)
    stderr_lines = tail_lines(stderr_path, limit=40)
    stderr_signal_lines = read_all_lines(stderr_path)
    stdout_text = "\n".join(stdout_lines)
    stderr_classification = classify_stderr_lines(stderr_signal_lines)
    last_progress = last_progress_payload_from_file(
        stdout_path,
        progress_prefix=progress_prefix,
    )
    last_entered_stage = last_entered_stage_from_file(
        stdout_path,
        progress_prefix=progress_prefix,
        stage_labels=stage_labels,
    )

    progress_stage = str(last_progress.get("stage", "") or "").strip() or last_entered_stage
    progress_failed_stage = str(last_progress.get("failed_stage", "")).strip()
    progress_message = str(last_progress.get("message", "")).strip()
    progress_reason_code = str(last_progress.get("failure_reason_code", "")).strip()
    progress_failure_reason = str(
        last_progress.get("failure_reason") or last_progress.get("error") or ""
    ).strip()
    progress_status = normalize_progress_status(
        last_progress.get("status") or last_progress.get("stage_status")
    )
    try:
        progress_percent = int(last_progress.get("percent", 0) or 0)
    except (TypeError, ValueError):
        progress_percent = 0
    progress_percent = max(0, min(100, progress_percent))

    report_href = ""
    dashboard_href = ""
    for line in stdout_lines:
        if line.startswith("Run report:"):
            report_href = path_to_output_href(line.split(":", 1)[1].strip())
        elif line.startswith("Dashboard index:"):
            dashboard_href = path_to_output_href(line.split(":", 1)[1].strip())

    base_url = str(config.get("base_url", "")).strip()
    hostname = str(config.get("hostname", "")).strip()
    if not hostname and base_url:
        hostname = urlparse(base_url).hostname or ""
    if not hostname and scope_entries:
        hostname = scope_entries[0].lstrip("*.")

    target_name = str(config.get("target_name", "")).strip()
    if not target_name and dashboard_href.startswith("/"):
        target_name = dashboard_href.lstrip("/").split("/", 1)[0]

    mode_name = str(config.get("mode", "idor") or "idor")
    enabled_modules = config.get("enabled_modules")
    if not isinstance(enabled_modules, list):
        enabled_modules = []

    stderr_warning_lines = _truncate_lines(stderr_classification.warnings)
    stderr_fatal_lines = _truncate_lines(
        [
            *stderr_classification.fatal_signal_lines,
            *stderr_classification.fatal_traceback_lines,
        ]
    )
    timeout_events = _truncate_lines(stderr_classification.timeout_events)

    status = "failed"
    status_message = "Recovered historical job from launcher artifacts"
    error = ""
    failed_stage = ""
    failure_reason_code = ""
    failure_reason = ""
    failure_step = ""
    stage = "startup"
    stage_label = "Recovered"
    recovered_percent = 0

    has_completion_marker = any(
        marker in stdout_text
        for marker in (
            "Run complete",
            "Finalizing run",
            "Run report:",
            "Deduplicated findings:",
        )
    )
    stop_requested_marker = stop_marker_path.exists()
    if has_completion_marker:
        status = "completed"
        status_message = "Run complete (recovered from artifacts)"
        stage = "completed"
        stage_label = "Completed"
        recovered_percent = 100
    elif (
        stop_requested_marker
        and not stderr_classification.has_fatal_signals
        and progress_status != "error"
        and not progress_failed_stage
        and not progress_reason_code
    ):
        status = "stopped"
        status_message = "Run stopped from dashboard control (recovered from artifacts)"
        stage = "completed"
        stage_label = stage_labels.get("completed", "Completed")
        recovered_percent = min(progress_percent, 99)
    else:
        status = "failed"
        interruption_error = "Pipeline run appears interrupted (no terminal completion marker in launcher artifacts)."
        if progress_stage or progress_message:
            failed_stage = progress_failed_stage or progress_stage or "startup"
            stage = failed_stage
            stage_label = stage_labels.get(stage, "Recovered")
            recovered_percent = min(progress_percent, 99)
            if progress_status == "error" or progress_failed_stage or progress_reason_code:
                status_message = progress_message or "Run failed (recovered from artifacts)"
                failure_reason_code = progress_reason_code or "pipeline_stage_error"
                failure_reason = (
                    progress_failure_reason or progress_message or "Recovered job failed"
                )
                error = failure_reason
            elif stderr_classification.has_fatal_signals:
                status_message = "Run failed (recovered from artifacts)"
                error = stderr_classification.best_fatal_line or "Recovered job failed"
                failure_reason_code = "pipeline_exit_nonzero"
                failure_reason = error
            else:
                status_message = "Run interrupted before completion (recovered from artifacts)"
                if stderr_signal_lines:
                    status_message = (
                        "Run interrupted after warning-only stderr degradation "
                        "(recovered from artifacts)"
                    )
                failure_reason_code = "pipeline_interrupted"
                failure_reason = progress_message or (
                    "Pipeline process ended before emitting a terminal completion event."
                )
                error = interruption_error
        elif stderr_classification.has_fatal_signals:
            status_message = "Run failed (recovered from artifacts)"
            failed_stage = progress_failed_stage or progress_stage or "unknown"
            stage = failed_stage
            stage_label = stage_labels.get(stage, "Recovered")
            recovered_percent = min(progress_percent, 99)
            error = stderr_classification.best_fatal_line or "Recovered job failed"
            failure_reason_code = progress_reason_code or "pipeline_exit_nonzero"
            failure_reason = progress_failure_reason or error
        else:
            status_message = "Run interrupted before completion (recovered from artifacts)"
            failed_stage = "startup"
            stage = "startup"
            stage_label = stage_labels.get("startup", "Recovered")
            recovered_percent = 0
            failure_reason_code = "pipeline_interrupted"
            failure_reason = "No terminal completion event found in launcher artifacts."
            error = interruption_error

    failure_step_defaults = {
        "subdomains": "src.recon.subdomains.enumerate_subdomains",
        "live_hosts": "src.recon.live_hosts.probe_live_hosts",
        "urls": "src.recon.urls.collect_urls",
    }
    if failed_stage:
        failure_step = failure_step_defaults.get(failed_stage, f"stage:{failed_stage}")

    timestamp_candidates: list[float] = []
    for candidate in (config_path, scope_path, stdout_path, stderr_path, stop_marker_path):
        if candidate.exists():
            try:
                timestamp_candidates.append(candidate.stat().st_mtime)
            except OSError:
                continue
    now = time.time()
    started_at = min(timestamp_candidates) if timestamp_candidates else now
    updated_at = max(timestamp_candidates) if timestamp_candidates else now
    finished_at = updated_at if status in {"completed", "failed", "stopped"} else None

    latest_logs = [*stdout_lines[-20:]]
    latest_logs.extend([f"stderr: {line}" for line in stderr_lines[-10:]])

    recovered = {
        "id": job_id,
        "base_url": base_url,
        "hostname": hostname,
        "scope_entries": scope_entries,
        "enabled_modules": enabled_modules,
        "mode": mode_name,
        "target_name": target_name,
        "status": status,
        "started_at": started_at,
        "updated_at": updated_at,
        "finished_at": finished_at,
        "stage": stage,
        "stage_label": stage_label,
        "status_message": status_message,
        "progress_percent": recovered_percent,
        "returncode": 0 if status == "completed" else 1,
        "error": error,
        "failed_stage": failed_stage,
        "failure_reason_code": failure_reason_code,
        "failure_step": failure_step,
        "failure_reason": failure_reason,
        "warnings": stderr_warning_lines,
        "stderr_warning_lines": stderr_warning_lines,
        "stderr_fatal_lines": stderr_fatal_lines,
        "timeout_events": timeout_events,
        "degraded_providers": extract_degraded_providers(stderr_classification.nonfatal_lines),
        "configured_timeout_seconds": None,
        "effective_timeout_seconds": None,
        "warning_count": int(stderr_classification.warning_count),
        "fatal_signal_count": int(stderr_classification.fatal_signal_count),
        "execution_options": {},
        "latest_logs": latest_logs[-40:],
        "config_href": f"/_launcher/{job_id}/config.json",
        "scope_href": f"/_launcher/{job_id}/scope.txt",
        "stdout_href": f"/_launcher/{job_id}/stdout.txt",
        "stderr_href": f"/_launcher/{job_id}/stderr.txt",
        "target_href": dashboard_href
        or (f"/{target_name}/index.html" if target_name else report_href),
        "stage_progress": {},
        "progress_telemetry": {
            "active_task_count": 0,
            "next_best_action": (
                "Open the generated report and review validated findings."
                if status == "completed"
                else "Inspect stdout/stderr launcher artifacts and re-run with --force-fresh-run."
            ),
            "event_triggers": ["artifact_recovery"],
            "last_update_epoch": updated_at,
        },
        "process": None,
        "stop_requested": False,
    }
    return recovered


def reconcile_stale_terminal_job(
    job: dict[str, Any],
    *,
    now: float,
    stalled_after_seconds: float,
    stage_labels: dict[str, str],
    recover_job_from_launcher: Callable[[str], dict[str, Any] | None],
    persist_callback: Callable[[dict[str, Any]], None],
    is_terminal_reporting_state_fn: Callable[[dict[str, Any]], bool],
    mark_running_stage_entries_completed_fn: Callable[[dict[str, Any], float], None],
) -> None:
    status = str(job.get("status", "")).strip().lower()
    job_id = str(job.get("id", "")).strip()

    if status == "failed":
        status_message = str(job.get("status_message", "")).strip().lower()
        error_text = str(job.get("error", "")).strip().lower()
        restart_interrupted = (
            "interrupted by dashboard restart" in status_message
            or "dashboard restarted while job was running" in error_text
        )
        if restart_interrupted and job_id:
            recovered_job = recover_job_from_launcher(job_id)
            recovered_status = (
                str(recovered_job.get("status", "")).strip().lower()
                if isinstance(recovered_job, dict)
                else ""
            )
            if recovered_status == "completed" and recovered_job is not None:
                job.clear()
                job.update(recovered_job)
                job["updated_at"] = now
                if job.get("finished_at") is None:
                    job["finished_at"] = now
                persist_callback(job)
        return

    if status != "running":
        return

    updated_at = _coerce_epoch(job.get("updated_at"), _coerce_epoch(job.get("started_at"), now))
    if (now - updated_at) < stalled_after_seconds:
        return

    process = job.get("process")
    process_returncode: int | None = None
    live_process_running = False
    if process is not None:
        try:
            poll = getattr(process, "poll", None)
            if callable(poll):
                polled = poll()
                if polled is None:
                    live_process_running = True
                else:
                    process_returncode = int(polled)
                    job["returncode"] = process_returncode
        except Exception:  # noqa: S110
            pass

    if not is_terminal_reporting_state_fn(job):
        if live_process_running:
            telemetry = job.get("progress_telemetry")
            if not isinstance(telemetry, dict):
                telemetry = {}
                job["progress_telemetry"] = telemetry
            event_triggers = _truncate_lines(
                [
                    *(telemetry.get("event_triggers", []) if isinstance(telemetry, dict) else []),  # type: ignore[arg-type]
                    "stalled_live_process_detected",
                ],
                limit=20,
            )
            telemetry["event_triggers"] = event_triggers
            telemetry["next_best_action"] = (
                "Run is still active but dashboard updates stalled; inspect live stdout/stderr before recovery."
            )
            persist_callback(job)
            return

        recovered_status_val: str | None = None
        recovered_job_data: dict[str, Any] | None = None
        if job_id:
            recovered_job_data = recover_job_from_launcher(job_id)
            recovered_status_val = (
                str(recovered_job_data.get("status", "")).strip().lower()
                if isinstance(recovered_job_data, dict)
                else ""
            )
        if recovered_status_val not in {"completed", "failed", "stopped"}:
            failed_stage = (
                str(job.get("failed_stage", "")).strip()
                or str(job.get("stage", "")).strip()
                or "startup"
            )
            job["status"] = "failed"
            job["stage"] = failed_stage
            job["stage_label"] = stage_labels.get(failed_stage, "Recovered")
            job["failed_stage"] = failed_stage
            try:
                current_percent = int(job.get("progress_percent", 0) or 0)
            except (TypeError, ValueError):
                current_percent = 0
            if current_percent >= 100:
                job["progress_percent"] = 99
            job["failure_reason_code"] = (
                str(job.get("failure_reason_code", "")).strip() or "stalled_without_terminal_marker"
            )
            failure_step_defaults = {
                "subdomains": "src.recon.subdomains.enumerate_subdomains",
                "live_hosts": "src.recon.live_hosts.probe_live_hosts",
                "urls": "src.recon.urls.collect_urls",
            }
            job["failure_step"] = str(
                job.get("failure_step", "")
            ).strip() or failure_step_defaults.get(failed_stage, f"stage:{failed_stage}")
            stalled_reason = (
                "Run stalled without a terminal completion marker; process is no longer "
                "active and launcher recovery did not provide terminal truth."
            )
            failure_reason = str(job.get("failure_reason", "")).strip() or stalled_reason
            job["failure_reason"] = failure_reason
            job["error"] = failure_reason
            job["status_message"] = (
                "Run stalled without terminal completion marker (auto-reconciled)"
            )
            if process_returncode is not None:
                job["returncode"] = process_returncode
            elif job.get("returncode") is None:
                job["returncode"] = 1
            job["process"] = None
            job["updated_at"] = now
            job["finished_at"] = now

            telemetry = job.get("progress_telemetry")
            if not isinstance(telemetry, dict):
                telemetry = {}
                job["progress_telemetry"] = telemetry
            telemetry["active_task_count"] = 0
            telemetry["event_triggers"] = _truncate_lines(
                [
                    *(telemetry.get("event_triggers", []) if isinstance(telemetry, dict) else []),  # type: ignore[arg-type]
                    "stalled_without_terminal_marker",
                ],
                limit=20,
            )
            telemetry["next_best_action"] = (
                "Inspect launcher stdout/stderr artifacts and re-run with --force-fresh-run."
            )
            telemetry["last_update_epoch"] = now

            latest_logs = [
                str(line or "").strip()
                for line in job.get("latest_logs", [])
                if str(line or "").strip()
            ]
            latest_logs.append("Run stalled without terminal completion marker (auto-reconciled)")
            job["latest_logs"] = latest_logs[-80:]

            persist_callback(job)
            return

        assert recovered_job is not None
        existing_process = job.get("process")
        job.clear()
        job.update(recovered_job)
        if existing_process is not None:
            try:
                terminate = getattr(existing_process, "terminate", None)
                if callable(terminate):
                    terminate()
            except Exception:  # noqa: S110
                pass
        job["process"] = None
        job["updated_at"] = now
        if job.get("finished_at") is None:
            job["finished_at"] = now
        persist_callback(job)
        return

    if process is not None:
        try:
            if process_returncode is not None:
                job["returncode"] = process_returncode
            else:
                terminate = getattr(process, "terminate", None)
                if callable(terminate):
                    terminate()
        except Exception:  # noqa: S110
            pass

    job["process"] = None
    job["status"] = "completed"
    job["stage"] = "completed"
    job["stage_label"] = stage_labels.get("completed", "Completed")
    job["status_message"] = "Run complete"
    job["progress_percent"] = 100
    job["finished_at"] = now
    job["updated_at"] = now
    job["error"] = ""
    job["failed_stage"] = ""
    job["failure_reason_code"] = ""
    job["failure_step"] = ""
    job["failure_reason"] = ""

    mark_running_stage_entries_completed_fn(job, now)

    telemetry = job.get("progress_telemetry")
    if not isinstance(telemetry, dict):
        telemetry = {}
        job["progress_telemetry"] = telemetry
    telemetry["active_task_count"] = 0
    telemetry["next_best_action"] = "Review findings and prioritize validated issues."
    telemetry["last_update_epoch"] = now

    targets = telemetry.get("targets")
    if isinstance(targets, dict):
        scanning = int(targets.get("scanning", 0) or 0)
        done = int(targets.get("done", 0) or 0)
        targets["scanning"] = 0
        targets["done"] = done + max(0, scanning)

    latest_logs = [
        str(line or "").strip() for line in job.get("latest_logs", []) if str(line or "").strip()
    ]
    latest_logs.append("Run complete (auto-reconciled from stalled terminal reporting state)")
    job["latest_logs"] = latest_logs[-80:]

    persist_callback(job)
