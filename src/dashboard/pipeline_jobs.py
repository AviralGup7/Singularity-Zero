"""Pipeline job management for the dashboard application.

Handles job record creation, subprocess launching, stream consumption,
and job lifecycle management for pipeline runs initiated from the dashboard.
"""

import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

from src.core.utils.safe_errors import safe_error_message
from src.core.utils.stderr_classification import classify_stderr_text, extract_degraded_providers
from src.dashboard.job_state import append_log, apply_progress
from src.dashboard.registry import PROGRESS_PREFIX, STAGE_LABELS


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
            "last_update_epoch": started_at,
        },
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


def _last_progress_payload_from_file(path: Path, *, progress_prefix: str) -> dict[str, Any]:
    try:
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
    except OSError:
        return {}

    last_payload: dict[str, Any] = {}
    for line in lines:
        if not line.startswith(progress_prefix):
            continue
        try:
            parsed = json.loads(line[len(progress_prefix) :])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            last_payload = parsed
    return last_payload


def consume_stream(
    job: dict[str, Any],
    stream: TextIO,
    sink: TextIO,
    source: str,
    lock: threading.Lock,
    persist_callback: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    def _persist_if_needed(*, force: bool = False) -> None:
        if persist_callback is None:
            return
        now = time.time()
        last_persist = float(job.get("_persist_last_epoch", 0.0) or 0.0)
        if not force and (now - last_persist) < 2.0:
            return
        job["_persist_last_epoch"] = now
        try:
            persist_callback(job)
        except Exception:  # noqa: S110
            # Persistence is best-effort and must not break pipeline execution.
            pass

    try:
        for raw_line in iter(stream.readline, ""):
            try:
                sink.write(raw_line)
                sink.flush()
                line = raw_line.rstrip()
                if not line:
                    continue
                if source == "stdout" and line.startswith(PROGRESS_PREFIX):
                    try:
                        payload = json.loads(line[len(PROGRESS_PREFIX) :])
                    except json.JSONDecodeError:
                        payload = None
                    if isinstance(payload, dict):
                        with lock:
                            apply_progress(job, payload)
                            _persist_if_needed()
                        continue

                with lock:
                    if source == "stderr" and line.lower().startswith("warning"):
                        warning_text = line.strip()
                        job["warnings"].append(warning_text)
                    job["warnings"] = job["warnings"][-6:]
                prefix = "stderr: " if source == "stderr" else ""
                append_log(job, f"{prefix}{line}")
            except Exception as exc:
                with lock:
                    append_log(job, f"Stream error ({source}): {exc}")
                    _persist_if_needed(force=True)
                break
    finally:
        stream.close()
        try:
            sink.close()
        except Exception:  # noqa: S110
            pass


def run_pipeline_job(
    workspace_root: Path,
    job: dict[str, Any],
    lock: threading.Lock,
    config_path: Path,
    scope_path: Path,
    stdout_path: Path,
    stderr_path: Path,
    persist_callback: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    def _persist(force: bool = False) -> None:
        if persist_callback is None:
            return
        now = time.time()
        last_persist = float(job.get("_persist_last_epoch", 0.0) or 0.0)
        if not force and (now - last_persist) < 2.0:
            return
        job["_persist_last_epoch"] = now
        try:
            persist_callback(job)
        except Exception:  # noqa: S110
            pass

    def _capture_forensics() -> None:
        job_id = str(job.get("id", "") or "").strip()
        if not job_id:
            return
        launcher_dir = config_path.parent
        if launcher_dir.name != job_id or launcher_dir.parent.name != "_launcher":
            return
        try:
            from src.dashboard.launcher_forensics import capture_launcher_replay_manifest

            capture_launcher_replay_manifest(
                launcher_dir.parent.parent,
                job_id,
                persisted_job=job,
            )
        except Exception:  # noqa: S110
            # Forensic capture is best-effort and must not change job outcome.
            pass

    def _truncate_lines(lines: list[str], *, limit: int = 6) -> list[str]:
        deduped: list[str] = []
        for line in lines:
            text = str(line or "").strip()
            if not text or text in deduped:
                continue
            deduped.append(text)
        return deduped[-limit:]

    def _extract_stdout_error_detail(stdout_text: str) -> str:
        if not stdout_text:
            return ""
        stdout_lines = stdout_text.splitlines()
        error_lines = [
            line
            for line in stdout_lines
            if line.strip()
            and (
                not line.strip().startswith(PROGRESS_PREFIX)
                and (
                    "error" in line.lower()
                    or "exception" in line.lower()
                    or "traceback" in line.lower()
                    or "fatal" in line.lower()
                    or line.lstrip().startswith("FATAL:")
                )
            )
        ]
        if not error_lines:
            return ""
        detail = chr(10).join(error_lines[-10:])
        if len(detail) > 500:
            detail = "..." + detail[-497:]
        return detail

    command = [
        sys.executable,
        "-m",
        "src.pipeline.runtime",
        "--config",
        str(config_path),
        "--scope",
        str(scope_path),
    ]
    execution_options = job.get("execution_options", {})
    if execution_options.get("refresh_cache"):
        command.append("--refresh-cache")
    if execution_options.get("skip_crtsh"):
        command.append("--skip-crtsh")
    if execution_options.get("dry_run"):
        command.append("--dry-run")
    # Dashboard launches should always start from explicit config/scope files.
    # Avoid restoring stale cross-run checkpoint metadata.
    command.append("--force-fresh-run")

    env = os.environ.copy()
    path_sep = os.pathsep
    candidate_bins = [
        str((workspace_root / ".tools" / "bin").resolve()),
        str((workspace_root / "tools" / "bin").resolve()),
        str((Path.home() / "go" / "bin").resolve()),
    ]
    existing_path = env.get("PATH", "")
    existing_parts = [part for part in existing_path.split(path_sep) if part]
    prepend_bins = [p for p in candidate_bins if p and p not in existing_parts and Path(p).exists()]
    if prepend_bins:
        env["PATH"] = path_sep.join([*prepend_bins, existing_path])

    process = None
    with lock:
        append_log(job, f"Launching: {' '.join(command)}")
        _persist(force=True)
    try:
        process = subprocess.Popen(  # noqa: S603
            command,
            cwd=str(workspace_root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        with lock:
            job["process"] = process
            _persist(force=True)
    except Exception as exc:  # noqa: BLE001
        if process is not None:
            try:
                process.kill()
                process.wait(timeout=5)
            except Exception:  # noqa: S110
                pass  # Process may already be dead
        safe_msg = safe_error_message(exc)
        with lock:
            job["status"] = "failed"
            job["finished_at"] = time.time()
            job["error"] = safe_msg
            job["failed_stage"] = "startup"
            job["failure_reason_code"] = "pipeline_start_exception"
            job["failure_step"] = "src.dashboard.pipeline_jobs.run_pipeline_job"
            job["failure_reason"] = safe_msg
            job["status_message"] = "Failed to start pipeline"
            job["progress_percent"] = job.get("progress_percent", 0)
            append_log(job, f"stderr: {safe_msg}")
            _persist(force=True)
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(safe_msg, encoding="utf-8")
        _capture_forensics()
        return

    with (
        stdout_path.open("w", encoding="utf-8") as stdout_handle,
        stderr_path.open("w", encoding="utf-8") as stderr_handle,
    ):
        consumers = [
            threading.Thread(
                target=consume_stream,
                args=(job, process.stdout, stdout_handle, "stdout", lock, persist_callback),
                daemon=True,
            ),
            threading.Thread(
                target=consume_stream,
                args=(job, process.stderr, stderr_handle, "stderr", lock, persist_callback),
                daemon=True,
            ),
        ]
        for consumer in consumers:
            consumer.start()

        returncode = process.wait()
        for consumer in consumers:
            consumer.join(timeout=10)

    # Small delay to ensure file handles are fully flushed
    import time as _time

    _time.sleep(0.5)

    # Capture process output for status/error reporting
    stdout_content = ""
    stderr_content = ""
    error_detail = ""
    stderr_classification = classify_stderr_text("")
    try:
        stderr_content = stderr_path.read_text(encoding="utf-8").strip()
        stderr_classification = classify_stderr_text(stderr_content)
        if stderr_classification.best_fatal_line:
            error_detail = safe_error_message(Exception(stderr_classification.best_fatal_line))
    except Exception:  # noqa: S110
        pass

    # If stderr is empty, also check stdout for error messages
    if not error_detail:
        try:
            stdout_content = stdout_path.read_text(encoding="utf-8").strip()
            error_detail = _extract_stdout_error_detail(stdout_content)
        except Exception:  # noqa: S110
            pass
    else:
        try:
            stdout_content = stdout_path.read_text(encoding="utf-8").strip()
        except Exception:  # noqa: S110
            stdout_content = ""

    no_pipeline_output = not stdout_content and not stderr_content
    last_progress = _last_progress_payload_from_file(stdout_path, progress_prefix=PROGRESS_PREFIX)
    str(last_progress.get("stage", "") or "").strip()
    progress_failed_stage = str(last_progress.get("failed_stage", "")).strip()
    progress_message = str(last_progress.get("message", "")).strip()
    progress_reason_code = str(last_progress.get("failure_reason_code", "")).strip()
    progress_failure_reason = str(
        last_progress.get("failure_reason") or last_progress.get("error") or ""
    ).strip()

    with lock:
        stop_requested = bool(job.get("stop_requested"))
        finished_at = time.time()
        job["returncode"] = returncode
        job["finished_at"] = finished_at
        job["updated_at"] = job["finished_at"]
        job["process"] = None
        if isinstance(job.get("_active_stages"), set):
            job["_active_stages"].clear()
        stderr_warning_lines = _truncate_lines(stderr_classification.warnings, limit=10)
        job["stderr_warning_lines"] = stderr_warning_lines
        job["stderr_fatal_lines"] = _truncate_lines(
            [
                *stderr_classification.fatal_signal_lines,
                *stderr_classification.fatal_traceback_lines,
            ],
            limit=10,
        )
        job["timeout_events"] = _truncate_lines(stderr_classification.timeout_events, limit=10)
        job["degraded_providers"] = extract_degraded_providers(stderr_classification.nonfatal_lines)
        job["warning_count"] = int(stderr_classification.warning_count)
        job["fatal_signal_count"] = int(stderr_classification.fatal_signal_count)
        job["warnings"] = list(stderr_warning_lines)

        # Ensure stage timeline is always present and terminal-safe.
        stage_progress = job.get("stage_progress")
        if not isinstance(stage_progress, dict):
            stage_progress = {}
            job["stage_progress"] = stage_progress
        if not stage_progress:
            stage_progress["startup"] = {
                "stage": "startup",
                "stage_label": STAGE_LABELS["startup"],
                "status": "completed",
                "processed": 0,
                "total": None,
                "percent": int(job.get("progress_percent", 0) or 0),
                "started_at": float(job.get("started_at", finished_at) or finished_at),
                "updated_at": finished_at,
            }

        # Check for any stages still in 'running' state
        has_running_stages = any(
            isinstance(sp, dict) and sp.get("status") == "running" for sp in stage_progress.values()
        )

        if stop_requested:
            job["status"] = "stopped"
        elif returncode == 0 and no_pipeline_output:
            job["status"] = "failed"
        elif returncode == 0 and has_running_stages:
            # Process exited cleanly but stages still running = incomplete
            job["status"] = "failed"
            job["failed_stage"] = next(
                (
                    name
                    for name, sp in stage_progress.items()
                    if isinstance(sp, dict) and sp.get("status") == "running"
                ),
                "unknown",
            )
            job["failure_reason"] = "Pipeline exited before all stages completed"
            job["failure_reason_code"] = "premature_exit"
        else:
            job["status"] = "completed" if returncode == 0 else "failed"
        job["progress_percent"] = (
            100 if job["status"] == "completed" else job.get("progress_percent", 0)
        )

        telemetry = job.get("progress_telemetry")
        if not isinstance(telemetry, dict):
            telemetry = {}
            job["progress_telemetry"] = telemetry

        if job["status"] == "completed":
            for sp in stage_progress.values():
                if isinstance(sp, dict) and sp.get("status") == "running":
                    sp["status"] = "completed"
                    sp["updated_at"] = finished_at
            job["stage"] = "completed"
            job["stage_label"] = STAGE_LABELS["completed"]
            job["status_message"] = "Run complete"
            job["error"] = ""
            job["failed_stage"] = ""
            job["failure_reason_code"] = ""
            job["failure_step"] = ""
            job["failure_reason"] = ""
            append_log(job, "Run complete")
            telemetry["active_task_count"] = 0
            telemetry["next_best_action"] = "Review findings and prioritize validated issues."
            telemetry["last_update_epoch"] = finished_at
        elif job["status"] == "stopped":
            for sp in stage_progress.values():
                if isinstance(sp, dict) and sp.get("status") == "running":
                    sp["status"] = "completed"
                    sp["updated_at"] = finished_at
            job["stage"] = "completed"
            job["stage_label"] = "Stopped"
            job["status_message"] = "Run stopped from dashboard control"
            job["error"] = ""
            job["failed_stage"] = ""
            job["failure_reason_code"] = ""
            job["failure_step"] = ""
            job["failure_reason"] = ""
            append_log(job, "Run stopped")
            telemetry["active_task_count"] = 0
            telemetry["next_best_action"] = "Restart the run to continue pipeline execution."
            telemetry["last_update_epoch"] = finished_at
        else:
            existing_failure_reason = str(job.get("failure_reason", "")).strip()
            failed_stage = str(job.get("failed_stage", "")).strip()
            if not failed_stage:
                failed_stage = str(job.get("stage", "")).strip() or "startup"
                job["failed_stage"] = failed_stage
            if not str(job.get("failure_step", "")).strip():
                failure_step_defaults = {
                    "subdomains": "src.recon.subdomains.enumerate_subdomains",
                    "live_hosts": "src.recon.live_hosts.probe_live_hosts",
                    "urls": "src.recon.urls.collect_urls",
                }
                job["failure_step"] = failure_step_defaults.get(
                    failed_stage, f"stage:{failed_stage}"
                )
            job["stage"] = failed_stage
            job["stage_label"] = STAGE_LABELS.get(failed_stage, "Run failed")

            for stage_key, sp in stage_progress.items():
                if not isinstance(sp, dict) or sp.get("status") != "running":
                    continue
                sp["status"] = "error"
                sp["updated_at"] = finished_at
                if stage_key == failed_stage and not sp.get("stage"):
                    sp["stage"] = failed_stage
            if failed_stage not in stage_progress:
                stage_progress[failed_stage] = {
                    "stage": failed_stage,
                    "stage_label": STAGE_LABELS.get(
                        failed_stage, failed_stage.replace("_", " ").title()
                    ),
                    "status": "error",
                    "processed": 0,
                    "total": None,
                    "percent": int(job.get("progress_percent", 0) or 0),
                    "started_at": float(job.get("started_at", finished_at) or finished_at),
                    "updated_at": finished_at,
                }

            # A failed run cannot be "completed" in stage timeline truth.
            completed_entry = stage_progress.get("completed")
            if isinstance(completed_entry, dict):
                completed_entry["status"] = "error"
                completed_entry["updated_at"] = finished_at
                completed_entry["reason"] = (
                    str(completed_entry.get("reason", "")).strip() or "pipeline_failed"
                )

            if returncode == 0 and no_pipeline_output:
                job["failure_reason_code"] = (
                    str(job.get("failure_reason_code", "")).strip() or "pipeline_no_output"
                )
                reason = "Pipeline process exited with code 0 but produced no output"
                job["failure_reason"] = str(job.get("failure_reason", "")).strip() or reason
                job["error"] = reason
                job["status_message"] = "Pipeline produced no output"
                append_log(job, "Pipeline produced no output; marking run as failed")
            elif progress_reason_code or progress_failure_reason:
                resolved_reason = (
                    existing_failure_reason
                    or progress_failure_reason
                    or progress_message
                    or error_detail
                    or f"Pipeline exited with code {returncode}"
                )
                if progress_failed_stage and not job.get("failed_stage"):
                    job["failed_stage"] = progress_failed_stage
                job["failure_reason_code"] = (
                    str(job.get("failure_reason_code", "")).strip()
                    or progress_reason_code
                    or "pipeline_stage_error"
                )
                job["failure_reason"] = (
                    str(job.get("failure_reason", "")).strip() or resolved_reason
                )
                job["error"] = resolved_reason
                job["status_message"] = (
                    progress_message or job.get("status_message") or "Pipeline failed"
                )
                append_log(job, f"Pipeline failed with exit code {returncode}")
                if error_detail:
                    append_log(job, f"Error: {error_detail[:200]}")
            elif error_detail:
                safe_detail = safe_error_message(Exception(error_detail))
                resolved_reason = existing_failure_reason or safe_detail
                job["failure_reason_code"] = (
                    str(job.get("failure_reason_code", "")).strip() or "pipeline_exit_nonzero"
                )
                job["failure_reason"] = (
                    str(job.get("failure_reason", "")).strip() or resolved_reason
                )
                job["error"] = resolved_reason
                current_message = str(job.get("status_message", "")).strip()
                if not current_message or current_message == "Creating config and scope":
                    job["status_message"] = f"Pipeline failed (exit code {returncode})"
                append_log(job, f"Pipeline failed with exit code {returncode}")
                append_log(job, f"Error: {error_detail[:200]}")
            elif stderr_content and not stderr_classification.has_fatal_signals:
                resolved_reason = (
                    existing_failure_reason
                    or progress_message
                    or "Pipeline exited after warning-only provider degradation without a terminal completion event."
                )
                job["failure_reason_code"] = (
                    str(job.get("failure_reason_code", "")).strip() or "pipeline_interrupted"
                )
                job["failure_reason"] = (
                    str(job.get("failure_reason", "")).strip() or resolved_reason
                )
                job["error"] = resolved_reason
                current_message = str(job.get("status_message", "")).strip()
                if not current_message or current_message == "Creating config and scope":
                    job["status_message"] = (
                        "Pipeline interrupted after warning-only provider degradation"
                    )
                append_log(job, f"Pipeline exited with code {returncode} after warning-only stderr")
            elif not job["status_message"] or job["status_message"] == "Creating config and scope":
                reason = f"Pipeline exited with code {returncode}"
                resolved_reason = existing_failure_reason or reason
                job["failure_reason_code"] = (
                    str(job.get("failure_reason_code", "")).strip() or "pipeline_exit_nonzero"
                )
                job["failure_reason"] = (
                    str(job.get("failure_reason", "")).strip() or resolved_reason
                )
                job["error"] = resolved_reason
                job["status_message"] = f"Pipeline exited with an error (code {returncode})"
                append_log(job, f"Pipeline exited with code {returncode}")
            else:
                reason = f"Pipeline exited with code {returncode}"
                resolved_reason = existing_failure_reason or reason
                job["failure_reason_code"] = (
                    str(job.get("failure_reason_code", "")).strip() or "pipeline_exit_nonzero"
                )
                job["failure_reason"] = (
                    str(job.get("failure_reason", "")).strip() or resolved_reason
                )
                job["error"] = resolved_reason
                append_log(job, f"Pipeline exited with code {returncode}")
            telemetry["active_task_count"] = 0
            telemetry["next_best_action"] = (
                "Inspect stdout/stderr artifacts and re-run with --force-fresh-run after fixing tool/environment issues."
            )
            telemetry["last_update_epoch"] = finished_at

        _persist(force=True)
        _capture_forensics()
