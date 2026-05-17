import json
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

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
        except Exception:  # noqa: S110, S112
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

    def load_template(self) -> dict[str, Any]:
        return load_template(self.config_template, self.output_root)

    def form_defaults(self) -> dict[str, str]:
        return build_form_defaults(self.load_template())

    def default_mode_name(self) -> str:
        return default_mode_name(self.load_template())

    def preset_module_names(self, mode_name: str) -> list[str]:
        return preset_module_names(self.load_template(), mode_name)

    def list_targets(self) -> list[dict[str, Any]]:
        if not self.output_root.exists():
            return []
        targets = []
        for entry in sorted(self.output_root.iterdir(), key=lambda item: item.name.lower()):
            if not entry.is_dir() or entry.name.startswith("_"):
                continue
            dashboard = entry / "index.html"
            if not dashboard.exists():
                continue
            latest_run = max(
                (
                    child.name
                    for child in entry.iterdir()
                    if child.is_dir() and (child / "run_summary.json").exists()
                ),
                default="",
            )
            latest_summary = self._read_latest_summary(entry, latest_run)
            counts = latest_summary.get("counts", {}) if isinstance(latest_summary, dict) else {}
            top_findings = (
                latest_summary.get("top_actionable_findings", [])
                if isinstance(latest_summary, dict)
                else []
            )
            trend = (
                latest_summary.get("trend_summary", {}) if isinstance(latest_summary, dict) else {}
            )
            top_finding = top_findings[0] if top_findings else {}
            attack_graph = (
                latest_summary.get("attack_graph", {}) if isinstance(latest_summary, dict) else {}
            )
            attack_chains = (
                attack_graph.get("chains", [])
                if isinstance(attack_graph.get("chains", []), list)
                else []
            )
            max_chain_confidence = 0.0
            for chain in attack_chains:
                confidence = float(chain.get("confidence", 0.0) or 0.0)
                if confidence > max_chain_confidence:
                    max_chain_confidence = confidence

            validation_results = (
                latest_summary.get("validation_results", {})
                if isinstance(latest_summary, dict)
                else {}
            )
            validation_plan_count = 0
            if isinstance(validation_results, dict):
                for items in validation_results.values():
                    if not isinstance(items, list):
                        continue
                    for finding in items:
                        if not isinstance(finding, dict):
                            continue
                        for action in finding.get("validation_actions", []):
                            if not isinstance(action, dict):
                                continue
                            plan = (
                                action.get("plan", {})
                                if isinstance(action.get("plan", {}), dict)
                                else {}
                            )
                            if isinstance(plan.get("steps", []), list) and plan.get("steps", []):
                                validation_plan_count += 1

            severity_counts: dict[str, int] = {}
            for finding in top_findings:
                if isinstance(finding, dict):
                    sev = str(finding.get("severity", "info")).strip().lower() or "info"
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1

            targets.append(
                {
                    "name": entry.name,
                    "href": f"/{entry.name}/index.html",
                    "latest_run": latest_run,
                    "latest_generated_at": (
                        str(latest_summary.get("generated_at_ist", "")).strip()
                        or format_iso_to_ist(
                            str(latest_summary.get("generated_at_utc", "")).strip()
                        )
                    )
                    if isinstance(latest_summary, dict)
                    else "",
                    "latest_report_href": f"/{entry.name}/{latest_run}/report.html"
                    if latest_run
                    else "",
                    "priority_url_count": int(counts.get("priority_urls", 0)) if counts else 0,
                    "finding_count": len(top_findings),
                    "validated_leads": int(counts.get("validated_leads", 0)) if counts else 0,
                    "url_count": int(counts.get("urls", 0)) if counts else 0,
                    "parameter_count": int(counts.get("parameters", 0)) if counts else 0,
                    "new_findings": int(trend.get("new_findings", 0)) if trend else 0,
                    "attack_chain_count": len(attack_chains),
                    "max_attack_chain_confidence": round(max_chain_confidence, 2),
                    "validation_plan_count": validation_plan_count,
                    "top_finding_title": str(top_finding.get("title", "")).strip(),
                    "top_finding_severity": str(top_finding.get("severity", "")).strip().lower(),
                    "top_finding_url": str(top_finding.get("url", "")).strip(),
                    "severity_counts": severity_counts,
                    "run_count": sum(
                        1
                        for child in entry.iterdir()
                        if child.is_dir() and (child / "run_summary.json").exists()
                    ),
                }
            )
        return targets

    def list_jobs(self) -> list[dict[str, Any]]:
        with self.lock:
            now = time.time()
            for job in self.jobs.values():
                self._reconcile_stale_terminal_job(job, now=now)
            items = [snapshot_job(job) for job in self.jobs.values()]
        return sorted(items, key=lambda item: item["started_at"], reverse=True)

    def _path_to_output_href(self, path_value: str) -> str:
        text = str(path_value or "").strip()
        if not text:
            return ""
        candidate = Path(text)
        if not candidate.is_absolute():
            candidate = (self.output_root / candidate).resolve()
        else:
            candidate = candidate.resolve()
        try:
            relative = candidate.relative_to(self.output_root.resolve())
            return f"/{relative.as_posix()}"
        except ValueError:
            return ""

    def _recover_job_from_launcher(self, job_id: str) -> dict[str, Any] | None:
        return recover_job_from_launcher(
            output_root=self.output_root,
            job_id=job_id,
            stage_labels=STAGE_LABELS,
            progress_prefix=PROGRESS_PREFIX,
            path_to_output_href=self._path_to_output_href,
        )

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        recovered: dict[str, Any] | None = None
        with self.lock:
            job = self.jobs.get(job_id)
            if job:
                self._reconcile_stale_terminal_job(job, now=time.time())
                return snapshot_job(job)
        recovered = self._recover_job_from_launcher(job_id)
        if not recovered:
            return None
        with self.lock:
            cached = self.jobs.setdefault(job_id, recovered)
            self._persist_if_needed(cached)
            return snapshot_job(cached)

    def stop_job(self, job_id: str) -> dict[str, Any]:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            process = job.get("process")
            if job.get("status") != "running" or process is None:
                return snapshot_job(job)
            job["stop_requested"] = True
            job["status_message"] = "Stopping run"
            marker_path = self.output_root / "_launcher" / job_id / "stop_requested.marker"
            try:
                marker_path.parent.mkdir(parents=True, exist_ok=True)
                marker_path.write_text(
                    json.dumps({"requested_at_epoch": time.time()}) + "\n",
                    encoding="utf-8",
                )
            except OSError:
                # Marker persistence is best-effort and should not block stop behavior.
                pass
        process.terminate()
        return self.get_job(job_id) or {}

    def api_defaults(self) -> dict[str, object]:
        config = self.load_template()
        return {
            "default_mode": default_mode_name(config),
            "preset_modules": {preset["name"]: list(preset["modules"]) for preset in MODE_PRESETS},
            "form_defaults": build_form_defaults(config),
        }

    def findings_summary(self) -> dict[str, object]:
        """Aggregate findings across all targets for a quick overview."""
        targets = self.list_targets()
        total_findings = 0
        severity_totals: dict[str, int] = {}
        targets_with_findings = 0
        for target in targets:
            count = target.get("finding_count", 0)
            total_findings += count
            if count > 0:
                targets_with_findings += 1
            for sev, cnt in target.get("severity_counts", {}).items():
                severity_totals[sev] = severity_totals.get(sev, 0) + cnt
        return {
            "total_findings": total_findings,
            "targets_with_findings": targets_with_findings,
            "severity_breakdown": severity_totals,
        }

    def detection_gap_summary(self, target_name: str | None = None) -> dict[str, object]:
        """Aggregate detection coverage data across targets or for a specific target."""
        targets = self.list_targets()
        if target_name:
            targets = [t for t in targets if t["name"] == target_name]

        all_active_modules: set[str] = set()
        all_empty_modules: set[str] = set()
        category_totals: dict[str, int] = {}
        signal_totals: dict[str, int] = {}
        coverage_scores: list[float] = []
        targets_analyzed = 0

        for target in targets:
            latest_run = target.get("latest_run", "")
            if not latest_run:
                continue
            target_dir = self.output_root / target["name"]
            summary_path = target_dir / latest_run / "run_summary.json"
            if not summary_path.exists():
                continue
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except Exception:  # noqa: S110, S112
                continue

            module_metrics = summary.get("module_metrics", {})
            if not isinstance(module_metrics, dict):
                continue

            analysis_metrics = module_metrics.get("analysis", {})
            detection_coverage = analysis_metrics.get("detection_coverage", {})
            if not detection_coverage:
                continue

            targets_analyzed += 1
            active = detection_coverage.get("active_modules", [])
            empty = detection_coverage.get("empty_modules", [])
            all_active_modules.update(active)
            all_empty_modules.update(empty)

            for cat, count in detection_coverage.get("coverage_by_category", {}).items():
                category_totals[cat] = category_totals.get(cat, 0) + count

            for sig, count in detection_coverage.get("signal_distribution", {}).items():
                signal_totals[sig] = signal_totals.get(sig, 0) + count

            score = detection_coverage.get("coverage_score", 0)
            if isinstance(score, (int, float)):
                coverage_scores.append(float(score))

        avg_coverage = round(sum(coverage_scores) / max(len(coverage_scores), 1), 2)
        return {
            "targets_analyzed": targets_analyzed,
            "coverage_score": avg_coverage,
            "active_modules": sorted(all_active_modules),
            "empty_modules": sorted(all_empty_modules),
            "active_module_count": len(all_active_modules),
            "empty_module_count": len(all_empty_modules),
            "coverage_by_category": dict(sorted(category_totals.items(), key=lambda x: -x[1])),
            "signal_distribution": dict(sorted(signal_totals.items(), key=lambda x: -x[1])[:20]),
        }

    @staticmethod
    def _read_latest_summary(target_dir: Path, latest_run: str) -> dict[str, Any]:
        if not latest_run:
            return {}
        summary_path = target_dir / latest_run / "run_summary.json"
        if not summary_path.exists():
            return {}
        try:
            result = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(result, dict):
                return result
            return {}
        except json.JSONDecodeError, OSError:
            return {}

    def get_timeline_data(self, target_id: str) -> list[dict[str, Any]]:
        """Get findings timeline data for a target sorted by timestamp.

        Args:
            target_id: Target directory name.

        Returns:
            List of finding dicts with timestamp, severity, category,
            url, title, confidence, and score, sorted by timestamp.
        """
        target_dir = self.output_root / target_id
        if not target_dir.exists():
            return []

        timeline: list[dict[str, Any]] = []
        run_dirs = sorted(
            (child for child in target_dir.iterdir() if child.is_dir()),
            key=lambda d: d.name,
        )

        for run_dir in run_dirs:
            findings_path = run_dir / "findings.json"
            if not findings_path.exists():
                continue

            try:
                findings = json.loads(findings_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError, OSError:
                continue

            run_timestamp = ""
            summary_path = run_dir / "run_summary.json"
            if summary_path.exists():
                try:
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    run_timestamp = summary.get("generated_at_utc", run_dir.name)
                except Exception:  # noqa: S110, S112
                    run_timestamp = run_dir.name

            if not isinstance(findings, list):
                continue

            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                timeline.append(
                    {
                        "timestamp": finding.get("timestamp", run_timestamp),
                        "severity": str(finding.get("severity", "info")).strip().lower(),
                        "category": str(finding.get("category", "")).strip(),
                        "url": str(finding.get("url", "")).strip(),
                        "title": str(finding.get("title", "")).strip(),
                        "confidence": finding.get("confidence", 0),
                        "score": finding.get("score", 0),
                        "run_id": run_dir.name,
                        "finding_id": finding.get("id", finding.get("finding_id", "")),
                    }
                )

        timeline.sort(key=lambda x: x.get("timestamp", ""))
        return timeline
