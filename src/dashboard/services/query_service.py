import json
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from src.core.utils import format_iso_to_ist
from src.dashboard.configuration import (
    build_form_defaults,
    default_mode_name,
    load_template,
    preset_module_names,
)
from src.dashboard.job_state import STALLED_AFTER_SECONDS, snapshot_job
from src.dashboard.registry import MODE_PRESETS, PROGRESS_PREFIX, STAGE_LABELS

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
            logger.error(
                "Persistence callback failed for job %s: %s",
                job.get("id", "unknown"),
                exc,
                exc_info=True,
            )
            # Reconciliation should never fail request handling.
            pass

    def _mark_running_stage_entries_completed(self, job: dict[str, Any], now: float) -> None:
        mark_running_stage_entries_completed(job, now, stage_labels=STAGE_LABELS)

    def _reconcile_stale_terminal_job(self, job: dict[str, Any], *, now: float) -> None:
        reconcile_stale_terminal_job(
            job,
            now=now,
            stalled_after_seconds=STALLED_AFTER_SECONDS,
            stage_labels=STAGE_LABELS,
            recover_job_from_launcher=self._recover_job_from_launcher,
            persist_callback=self._persist_if_needed,
            is_terminal_reporting_state_fn=self._is_terminal_reporting_state,
            mark_running_stage_entries_completed_fn=self._mark_running_stage_entries_completed,
        )

    def _path_to_output_href(self, path_str: str) -> str:
        """Convert a physical output path to a dashboard-relative HREF."""
        try:
            path = Path(path_str).resolve()
            # If the path is within output_root, make it relative
            if path.is_relative_to(self.output_root):
                rel = path.relative_to(self.output_root)
                return f"/{rel.as_posix()}"
            return path_str
        except (ValueError, RuntimeError):
            return path_str

    def _recover_job_from_launcher(self, job_id: str) -> dict[str, Any] | None:
        return recover_job_from_launcher(
            output_root=self.output_root,
            job_id=job_id,
            stage_labels=STAGE_LABELS,
            progress_prefix=PROGRESS_PREFIX,
            path_to_output_href=self._path_to_output_href,
        )

    def load_template(self) -> dict[str, Any]:
        return load_template(self.config_template, self.output_root)

    def get_form_defaults(self, target_url: str | None = None) -> dict[str, Any]:
        config = self.load_template()
        if target_url:
            config["base_url"] = target_url
        return build_form_defaults(config)

    def form_defaults(self) -> dict[str, str]:
        return self.get_form_defaults()

    def default_mode_name(self) -> str:
        return default_mode_name(self.load_template())

    def get_mode_preset(self, mode: str) -> dict[str, Any]:
        presets = {p["name"]: p for p in MODE_PRESETS}
        return cast(dict[str, Any], presets.get(mode, presets[self.default_mode_name()]))

    def get_preset_modules(self, mode: str) -> list[str]:
        return preset_module_names(self.load_template(), mode)

    def preset_module_names(self, mode: str) -> list[str]:
        return self.get_preset_modules(mode)

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
                job = self._recover_job_from_launcher(job_id)
                if job:
                    self.jobs[job_id] = job

            if job:
                if job.get("status") in {"running", "failed"}:
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

    def stop_job(self, job_id: str) -> dict[str, Any]:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError(job_id)

            if job.get("status") == "running":
                process = job.get("process")
                if process:
                    try:
                        terminate = getattr(process, "terminate", None)
                        if callable(terminate):
                            terminate()
                    except Exception as exc:
                        logger.debug("Failed to terminate process for job %s: %s", job_id, exc)

                job["status"] = "stopped"
                job["status_message"] = "Stopping run"
                job["stop_requested"] = True
                job["finished_at"] = time.time()
                job["updated_at"] = time.time()

                # Write stop marker artifact for historical recovery
                launcher_dir = self.output_root / "_launcher" / job_id
                if launcher_dir.exists():
                    try:
                        (launcher_dir / "stop_requested.marker").write_text(
                            str(time.time()), encoding="utf-8"
                        )
                    except OSError as exc:
                        logger.warning("Failed to write stop marker for %s: %s", job_id, exc)

                self._persist_if_needed(job)

            return snapshot_job(job)

    def api_defaults(self) -> dict[str, object]:
        config = self.load_template()
        return {
            "default_mode": self.default_mode_name(),
            "form_defaults": {
                "httpx_threads": config.get("httpx", {}).get("threads", 80),
                "refresh_cache": False,
                "auto_max_speed_mode": config.get("analysis", {}).get("auto_max_speed_mode", False),
                "httpx_batch_concurrency": config.get("httpx", {}).get("batch_concurrency", 2),
                "httpx_fallback_threads": config.get("httpx", {}).get("fallback_threads", 48),
                "httpx_probe_timeout_seconds": config.get("httpx", {}).get(
                    "probe_timeout_seconds", 8
                ),
                "pagination_walk_limit": config.get("analysis", {}).get(
                    "pagination_walk_limit", 24
                ),
                "options_probe_limit": config.get("analysis", {}).get("options_probe_limit", 10),
            },
            "http_timeout_seconds": config.get("http_timeout_seconds", 12),
            "max_collected_urls": config.get("filters", {}).get("max_collected_urls", 1400),
            "request_rate_per_second": config.get("analysis", {}).get(
                "request_rate_per_second", 2.5
            ),
        }

    def findings_summary(self) -> dict[str, object]:
        return {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

    def detection_gap_summary(self, target_name: str | None = None) -> dict[str, object]:
        """Aggregate real telemetry across runs to compute coverage and gaps."""
        # Normalize special target names
        if target_name in ("all", ""):
            target_name = None

        targets_to_process = []
        if target_name:
            target_dir = self.output_root / target_name
            if target_dir.exists() and target_dir.is_dir():
                targets_to_process.append(target_name)
        else:
            # List all target directories
            if self.output_root.exists():
                for entry in self.output_root.iterdir():
                    if entry.is_dir() and not entry.name.startswith("_"):
                        targets_to_process.append(entry.name)

        active_modules: set[str] = set()
        empty_modules: set[str] = set()
        coverage_by_category: dict[str, int] = {}

        for target in targets_to_process:
            target_dir = self.output_root / target
            run_dirs = sorted(
                [
                    d
                    for d in target_dir.iterdir()
                    if d.is_dir() and (d / "run_summary.json").exists()
                ],
                key=lambda x: x.name,
                reverse=True,
            )
            if not run_dirs:
                continue

            latest_run_dir = run_dirs[0]
            summary_path = latest_run_dir / "run_summary.json"
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                coverage = summary.get("detection_coverage") or {}

                run_active = coverage.get("active_modules") or []
                run_empty = coverage.get("empty_modules") or []
                run_cat_counts = coverage.get("coverage_by_category") or {}

                # Fallback to counts if detection_coverage is missing
                if not run_active and not run_empty:
                    counts = summary.get("counts") or {}
                    for k, v in counts.items():
                        if k not in {
                            "scope_entries",
                            "subdomains",
                            "live_hosts",
                            "urls",
                            "parameters",
                            "priority_urls",
                            "screenshots",
                            "attack_campaigns",
                            "validation_results",
                            "validated_leads",
                            "vrt_direct",
                            "vrt_signal_only",
                            "vrt_disabled",
                            "vrt_unsupported",
                        }:
                            if isinstance(v, int) and v > 0:
                                run_active.append(k)
                            else:
                                run_empty.append(k)

                active_modules.update(run_active)
                empty_modules.update(run_empty)

                for cat, count in run_cat_counts.items():
                    coverage_by_category[cat] = coverage_by_category.get(cat, 0) + count
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("Failed to read run_summary.json for %s: %s", target, exc)
                continue

        # Standardize modules by removing active modules from empty modules list
        final_empty = sorted(list(empty_modules - active_modules))

        return {
            "active_modules": sorted(list(active_modules)),
            "empty_modules": final_empty,
            "coverage_by_category": coverage_by_category,
        }

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
                [d for d in entry.iterdir() if d.is_dir() and (d / "run_summary.json").exists()],
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
                analysis_metrics = (
                    summary.get("metrics", {}).get("analysis")
                    or summary.get("metrics", {}).get("passive_scan")
                    or {}
                )

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
