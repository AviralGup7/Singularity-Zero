import json
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from src.core.utils import format_iso_to_ist
from src.dashboard.configuration import (
    build_form_defaults,
    default_mode_name,
    preset_module_names,
)
from src.dashboard.job_state import STALLED_AFTER_SECONDS, snapshot_job
from src.dashboard.registry import MODE_PRESETS, STAGE_LABELS

from .query_service_recovery import (
    is_terminal_reporting_state,
    mark_running_stage_entries_completed,
    reconcile_stale_terminal_job,
    recover_job_from_launcher,
)

logger = logging.getLogger(__name__)


class DashboardQueryService:
    def __init__(
        self,
        *,
        output_root: Path,
        config_template: Path,
        lock: threading.Lock,
        jobs: dict[str, dict[str, Any]],
        persist_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.output_root = output_root
        self.config_template = config_template
        self.lock = lock
        self.jobs = jobs
        self.persist_callback = persist_callback

    def _is_terminal_reporting_state(self, job: dict[str, Any]) -> bool:
        return is_terminal_reporting_state(job, stage_labels=STAGE_LABELS)

    def _persist_if_needed(self, job: dict[str, Any]) -> None:
        if self.persist_callback is None:
            return
        try:
            self.persist_callback(job)
        except Exception as exc:  # noqa: S110, S112
            logger.debug("Persistence callback failed: %s", exc)
            # Reconciliation should never fail request handling.
            pass

    def _mark_running_stage_entries_completed(self, job: dict[str, Any], now: float) -> None:
        mark_running_stage_entries_completed(job, now, stage_labels=STAGE_LABELS)

    def _reconcile_stale_terminal_job(self, job: dict[str, Any], *, now: float) -> None:
        reconcile_stale_terminal_job(
            job,
            now=now,
            stage_labels=STAGE_LABELS,
            output_root=self.output_root,
        )

    def get_form_defaults(self, target_url: str | None = None) -> dict[str, Any]:
        return build_form_defaults(
            target_url,
            template_path=self.config_template,
            presets=MODE_PRESETS,
        )

    def get_mode_preset(self, mode: str) -> dict[str, Any]:
        return MODE_PRESETS.get(mode, MODE_PRESETS[default_mode_name(MODE_PRESETS)])

    def get_preset_modules(self, mode: str) -> list[str]:
        return preset_module_names(mode, presets=MODE_PRESETS)

    def list_jobs(self) -> list[dict[str, Any]]:
        now = time.time()
        with self.lock:
            for job in self.jobs.values():
                if self._is_terminal_reporting_state(job):
                    continue

                self._reconcile_stale_terminal_job(job, now=now)

                elapsed = now - float(job.get("updated_at", 0) or 0)
                job["stalled"] = not self._is_terminal_reporting_state(job) and (
                    elapsed > STALLED_AFTER_SECONDS
                )
                if job["stalled"]:
                    job["elapsed_seconds"] = int(elapsed)
                    job["elapsed_label"] = f"{int(elapsed)}s"

                job["has_eta"] = (
                    job.get("status") == "running"
                    and job.get("progress_percent", 0) > 5
                    and job.get("started_at")
                )
                if job["has_eta"]:
                    start = float(job["started_at"])
                    progress = float(job["progress_percent"]) / 100
                    total_est = (now - start) / progress
                    eta_sec = total_est - (now - start)
                    job["eta_label"] = f"{int(eta_sec // 60)}m {int(eta_sec % 60)}s"

            return [snapshot_job(j) for j in self.jobs.values()]

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        now = time.time()
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                # Fallback: check if we can recover it from the output directory
                job = recover_job_from_launcher(job_id, workspace_root=self.output_root.parent)
                if job:
                    self.jobs[job_id] = job

            if job:
                if not self._is_terminal_reporting_state(job):
                    self._reconcile_stale_terminal_job(job, now=now)

                elapsed = now - float(job.get("updated_at", 0) or 0)
                job["stalled"] = not self._is_terminal_reporting_state(job) and (
                    elapsed > STALLED_AFTER_SECONDS
                )
                if job["stalled"]:
                    job["elapsed_seconds"] = int(elapsed)
                    job["elapsed_label"] = f"{int(elapsed)}s"

                return snapshot_job(job)
        return None

    def list_targets(self) -> list[dict[str, Any]]:
        targets = []
        if not self.output_root.exists():
            return []

        for entry in sorted(self.output_root.iterdir(), key=lambda x: x.name.lower()):
            if not entry.is_dir() or entry.name.startswith("_"):
                continue

            last_run = ""
            run_count = 0
            total_findings = 0
            last_updated = ""

            run_dirs = sorted(
                [
                    d
                    for d in entry.iterdir()
                    if d.is_dir() and (d / "run_summary.json").exists()
                ],
                key=lambda x: x.name,
                reverse=True,
            )

            if run_dirs:
                run_count = len(run_dirs)
                last_run_dir = run_dirs[0]
                last_run = last_run_dir.name
                summary_path = last_run_dir / "run_summary.json"
                try:
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    total_findings = summary.get("total_findings", 0)
                    last_updated = format_iso_to_ist(
                        summary.get("generated_at_utc", last_run_dir.name)
                    )
                except (json.JSONDecodeError, OSError) as exc:
                    logger.debug("Failed to read run_summary.json for %s: %s", entry.name, exc)
                    continue

            targets.append(
                {
                    "name": entry.name,
                    "last_run": last_run,
                    "run_count": run_count,
                    "total_findings": total_findings,
                    "last_updated": last_updated,
                }
            )
        return targets

    def get_timeline_data(self, target_name: str) -> list[dict[str, Any]]:
        target_dir = self.output_root / target_name
        if not target_dir.exists():
            return []

        timeline = []
        run_dirs = sorted(
            [d for d in target_dir.iterdir() if d.is_dir() and (d / "run_summary.json").exists()],
            key=lambda x: x.name,
        )

        for run_dir in run_dirs:
            summary_path = run_dir / "run_summary.json"
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                run_timestamp = summary.get("generated_at_utc", run_dir.name)

                # Gap Analysis Fix: Metrics now resolve from both 'analysis' and 'passive_scan' keys
                # This ensures telemetry matches backend field naming during frontier mesh runs.
                analysis_metrics = summary.get("metrics", {}).get("analysis") or summary.get("metrics", {}).get("passive_scan") or {}

                timeline.append(
                    {
                        "run_id": run_dir.name,
                        "timestamp": run_timestamp,
                        "total_findings": summary.get("total_findings", 0),
                        "critical": summary.get("severity_counts", {}).get("critical", 0),
                        "high": summary.get("severity_counts", {}).get("high", 0),
                        "medium": summary.get("severity_counts", {}).get("medium", 0),
                        "low": summary.get("severity_counts", {}).get("low", 0),
                        "info": summary.get("severity_counts", {}).get("info", 0),
                        "duration_sec": summary.get("duration_sec", 0),
                        "urls_found": analysis_metrics.get("urls_found", 0),
                    }
                )
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("Failed to read run_summary.json in %s: %s", run_dir.name, exc)
                continue

        return timeline

    def get_target_history(self, target_name: str) -> list[dict[str, Any]]:
        target_dir = self.output_root / target_name
        if not target_dir.exists():
            return []

        history = []
        run_dirs = sorted(
            [d for d in target_dir.iterdir() if d.is_dir() and (d / "run_summary.json").exists()],
            key=lambda x: x.name,
            reverse=True,
        )

        for run_dir in run_dirs:
            summary_path = run_dir / "run_summary.json"
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                history.append(
                    {
                        "run_id": run_dir.name,
                        "timestamp": summary.get("generated_at_utc", run_dir.name),
                        "summary": summary,
                    }
                )
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("Failed to read run_summary.json in %s: %s", run_dir.name, exc)
                continue

        return history
