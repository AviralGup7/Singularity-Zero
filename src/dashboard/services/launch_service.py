import json
import threading
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from src.dashboard.configuration import (
    apply_mode_selection,
    apply_module_selection,
    apply_runtime_overrides,
)
from src.dashboard.job_state import snapshot_job
from src.dashboard.pipeline_jobs import create_job_record, run_pipeline_job
from src.dashboard.utils import (
    build_scope_entries,
    build_scope_entries_from_text,
    normalize_base_url,
    root_domain,
    slugify,
)

from .query_service import DashboardQueryService

DISCOVERY_MODULES = {"subfinder", "assetfinder", "amass"}


class DashboardLaunchService:
    def __init__(
        self,
        *,
        workspace_root: Path,
        output_root: Path,
        lock: threading.Lock,
        jobs: dict[str, dict[str, Any]],
        query_service: DashboardQueryService,
        persist_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.workspace_root = workspace_root
        self.output_root = output_root
        self.lock = lock
        self.jobs = jobs
        self.query_service = query_service
        self.persist_callback = persist_callback

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
        pasted_scope = scope_text.strip()
        normalized_url = ""
        hostname = ""
        if base_url.strip():
            normalized_url, hostname = normalize_base_url(base_url)
        elif not pasted_scope:
            raise ValueError("Enter a base URL or paste a bug bounty scope block.")

        job_id = uuid.uuid4().hex[:8]
        launcher_dir = self.output_root / "_launcher" / job_id
        launcher_dir.mkdir(parents=True, exist_ok=True)

        config = self.query_service.load_template()
        selected_mode = (mode_name or self.query_service.default_mode_name()).strip().lower()
        apply_mode_selection(config, selected_mode)
        enabled_modules = list(
            dict.fromkeys(selected_modules or self.query_service.preset_module_names(selected_mode))
        )
        expand_subdomains = any(module in DISCOVERY_MODULES for module in enabled_modules)
        scope_entries = (
            build_scope_entries_from_text(pasted_scope, fallback_hostname=hostname)
            if pasted_scope
            else build_scope_entries(hostname, expand_subdomains=expand_subdomains)
        )
        primary_scope = scope_entries[0].lstrip("*.") if scope_entries else hostname
        if not hostname:
            hostname = primary_scope
        if not normalized_url:
            normalized_url = f"https://{primary_scope}"
        target_name = slugify(root_domain(primary_scope))
        config["target_name"] = target_name
        config["output_dir"] = str(self.output_root)
        apply_module_selection(config, set(enabled_modules))
        if runtime_overrides:
            apply_runtime_overrides(config, runtime_overrides)

        config_path = launcher_dir / "config.json"
        scope_path = launcher_dir / "scope.txt"
        stdout_path = launcher_dir / "stdout.txt"
        stderr_path = launcher_dir / "stderr.txt"

        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        scope_path.write_text("\n".join(scope_entries) + "\n", encoding="utf-8")

        job = create_job_record(
            job_id,
            normalized_url,
            hostname,
            scope_entries,
            enabled_modules,
            target_name,
            selected_mode,
            execution_options=execution_options,
        )
        with self.lock:
            self.jobs[job_id] = job

        worker = threading.Thread(
            target=run_pipeline_job,
            args=(
                self.workspace_root,
                job,
                self.lock,
                config_path,
                scope_path,
                stdout_path,
                stderr_path,
                self.persist_callback,
            ),
            daemon=True,
        )
        worker.start()
        return snapshot_job(job)
