import logging
import threading
from pathlib import Path
from typing import Any

from src.dashboard.job_store import JobStore

from .launch_service import DashboardLaunchService
from .query_service import DashboardQueryService


class DashboardServices:
    def __init__(self, workspace_root: Path, output_root: Path, config_template: Path):
        self.lock = threading.Lock()
        self.jobs: dict[str, dict[str, Any]] = {}
        self._job_store: JobStore | None = None  # Set externally via init_persistence()
        self.query = DashboardQueryService(
            output_root=output_root,
            config_template=config_template,
            lock=self.lock,
            jobs=self.jobs,
            persist_callback=self._persist_job,
        )
        self.launch = DashboardLaunchService(
            workspace_root=workspace_root,
            output_root=output_root,
            lock=self.lock,
            jobs=self.jobs,
            query_service=self.query,
            persist_callback=self._persist_job,
        )

    def init_persistence(self, db_path: Path | None = None) -> None:
        """Initialize SQLite-backed job persistence.

        Loads existing jobs from disk and marks stale running jobs as failed.
        """
        from src.dashboard.job_store import JobStore
        from src.dashboard.launcher_forensics import (
            merge_persisted_job_with_recovered_truth,
            persisted_job_has_truth_drift,
        )

        if db_path is None:
            db_path = Path("output") / "jobs.db"

        self._job_store = JobStore(db_path)

        # Mark any stale running jobs as failed before loading them into memory.
        stale_count = self._job_store.mark_stale_running()
        if stale_count:
            logging.getLogger(__name__).warning(
                "Marked %d stale running job(s) as failed after restart", stale_count
            )

        # Load existing jobs from disk
        persisted = self._job_store.load_all()
        with self.lock:
            self.jobs.update(persisted)

        recovered_missing_count = 0
        launcher_root = self.query.output_root / "_launcher"
        if launcher_root.exists():
            for launcher_dir in sorted(
                (path for path in launcher_root.iterdir() if path.is_dir()),
                key=lambda path: path.name,
            ):
                job_id = launcher_dir.name
                if not job_id or job_id in self.jobs:
                    continue
                recovered_job = self.query._recover_job_from_launcher(job_id)
                if not recovered_job:
                    continue
                with self.lock:
                    self.jobs[job_id] = recovered_job
                self._persist_job(recovered_job)
                recovered_missing_count += 1
        if recovered_missing_count:
            logging.getLogger(__name__).warning(
                "Recovered %d launcher job(s) missing from persistence",
                recovered_missing_count,
            )

        reconciled_count = 0
        for job_id, persisted_job in list(self.jobs.items()):
            recovered_job = self.query._recover_job_from_launcher(job_id)
            if not recovered_job:
                continue
            if not persisted_job_has_truth_drift(persisted_job, recovered_job):
                continue
            merged_job = merge_persisted_job_with_recovered_truth(
                persisted_job,
                recovered_job,
            )
            with self.lock:
                self.jobs[job_id] = merged_job
            self._persist_job(merged_job)
            reconciled_count += 1
        if reconciled_count:
            logging.getLogger(__name__).warning(
                "Reconciled %d persisted job(s) from launcher artifacts",
                reconciled_count,
            )

        # Clean up old jobs (older than 30 days)
        self._job_store.cleanup_old(max_age_days=30)

    def close_persistence(self) -> None:
        """Close SQLite connections."""
        if hasattr(self, "_job_store") and self._job_store is not None:
            self._job_store.close()

    def _persist_job(self, job: dict[str, Any]) -> None:
        """Persist a job record to the SQLite store."""
        if self._job_store:
            try:
                self._job_store.save(job)
            except Exception as exc:
                import logging

                logging.getLogger(__name__).warning(
                    "Failed to persist job %s: %s", job.get("id"), exc
                )

    def load_template(self) -> dict[str, Any]:
        return self.query.load_template()

    def form_defaults(self) -> dict[str, str]:
        return self.query.form_defaults()

    def default_mode_name(self) -> str:
        return self.query.default_mode_name()

    def preset_module_names(self, mode_name: str) -> list[str]:
        return self.query.preset_module_names(mode_name)

    def list_targets(self) -> list[dict[str, Any]]:
        return self.query.list_targets()

    def list_jobs(self) -> list[dict[str, Any]]:
        return self.query.list_jobs()

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        return self.query.get_job(job_id)

    def stop_job(self, job_id: str) -> dict[str, Any]:
        return self.query.stop_job(job_id)

    @staticmethod
    def _validate_restart_base_url(existing: dict[str, Any], job_id: str) -> str:
        """Validate that a job has a base_url before restarting."""
        base_url = str(existing.get("base_url", "") or "").strip()
        if not base_url:
            raise ValueError(f"Job {job_id} has no base_url and cannot be restarted")
        return base_url

    def restart_job_safe(self, job_id: str) -> dict[str, Any]:
        existing = self.query.get_job(job_id)
        if not existing:
            raise KeyError(job_id)

        if existing.get("status") == "running":
            self.query.stop_job(job_id)

        scope_entries = [
            str(item).strip() for item in existing.get("scope_entries", []) if str(item).strip()
        ]
        scope_text = "\n".join(scope_entries)
        execution_options = dict(existing.get("execution_options", {}))
        execution_options["skip_crtsh"] = True
        execution_options["refresh_cache"] = False

        # Preserve original runtime overrides from the job record
        runtime_overrides = dict(existing.get("runtime_overrides", {}))

        return self.launch.start(
            self._validate_restart_base_url(existing, job_id),
            scope_text=scope_text,
            selected_modules=list(existing.get("enabled_modules", [])),
            mode_name=str(existing.get("mode", "") or ""),
            runtime_overrides=runtime_overrides or None,
            execution_options=execution_options,
        )

    def api_defaults(self) -> dict[str, object]:
        return self.query.api_defaults()

    def findings_summary(self) -> dict[str, object]:
        return self.query.findings_summary()

    def detection_gap_summary(self, target_name: str | None = None) -> dict[str, object]:
        return self.query.detection_gap_summary(target_name)

    def start(
        self,
        base_url: str,
        *,
        scope_text: str = "",
        selected_modules: list[str] | None = None,
        mode_name: str | None = None,
        runtime_overrides: dict[str, str] | None = None,
        execution_options: dict[str, bool] | None = None,
    ) -> dict[str, Any]:
        result = self.launch.start(
            base_url,
            scope_text=scope_text,
            selected_modules=selected_modules,
            mode_name=mode_name,
            runtime_overrides=runtime_overrides,
            execution_options=execution_options,
        )
        # Persist the newly created job
        job_id = result.get("id")
        if job_id and self.jobs.get(job_id):
            self._persist_job(self.jobs[job_id])
        return result
