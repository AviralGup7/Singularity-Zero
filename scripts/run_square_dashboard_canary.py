from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from src.dashboard.configuration import default_mode_name, default_module_names, load_template
from src.dashboard.launcher_forensics import (
    SQUARE_REFERENCE_JOB_ID,
    build_launcher_replay_manifest,
    capture_launcher_replay_manifest,
    compare_launcher_replay_manifests,
)
from src.dashboard.services import DashboardServices

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _default_output_root(workspace_root: Path) -> Path:
    return workspace_root / "src" / "dashboard" / "output"


def _default_config_template(output_root: Path) -> Path:
    reference_config = output_root / "_launcher" / SQUARE_REFERENCE_JOB_ID / "config.json"
    if reference_config.exists():
        return reference_config
    return Path("configs") / "config.example.json"


def _default_scope_file(output_root: Path) -> Path:
    reference_scope = output_root / "_launcher" / SQUARE_REFERENCE_JOB_ID / "scope.txt"
    if reference_scope.exists():
        return reference_scope
    return Path("src") / "dashboard" / "config" / "squareup-scope.txt"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _wait_for_terminal_job_state(
    services: DashboardServices,
    job_id: str,
    *,
    current: dict[str, Any],
    poll_seconds: float,
    timeout_seconds: float,
) -> dict[str, Any]:
    latest = current
    deadline = time.monotonic() + max(timeout_seconds, 1.0)
    while time.monotonic() < deadline:
        latest = services.get_job(job_id) or latest
        if str(latest.get("status", "") or "") != "running":
            return latest
        time.sleep(max(poll_seconds, 1.0))
    return latest


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the square.com dashboard launcher path as a replayable canary."
    )
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-root", type=Path, default=None)
    parser.add_argument("--config-template", type=Path, default=None)
    parser.add_argument("--scope-file", type=Path, default=None)
    parser.add_argument("--base-url", default="")
    parser.add_argument("--mode", default="")
    parser.add_argument("--poll-seconds", type=float, default=15.0)
    parser.add_argument("--timeout-seconds", type=float, default=7200.0)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    workspace_root = args.workspace_root.resolve()
    output_root = (args.output_root or _default_output_root(workspace_root)).resolve()
    config_template = (args.config_template or _default_config_template(output_root)).resolve()
    scope_file = (args.scope_file or _default_scope_file(output_root)).resolve()
    scope_text = scope_file.read_text(encoding="utf-8")
    template = load_template(config_template, output_root)
    mode_name = args.mode.strip() or default_mode_name(template)
    selected_modules = default_module_names(template)

    services = DashboardServices(workspace_root, output_root, config_template)
    services.init_persistence(output_root / "jobs.db")
    job_id = ""
    result_path: Path | None = None
    try:
        job = services.start(
            args.base_url,
            scope_text=scope_text,
            selected_modules=selected_modules,
            mode_name=mode_name,
            execution_options={
                "refresh_cache": False,
                "skip_crtsh": False,
                "dry_run": False,
            },
        )
        job_id = str(job.get("id", "") or "")
        result_path = output_root / "_launcher" / job_id / "canary_result.json"
        print(f"job_id={job_id}", flush=True)
        print(f"launcher_dir={output_root / '_launcher' / job_id}", flush=True)

        deadline = time.monotonic() + max(args.timeout_seconds, 1.0)
        last_line = ""
        current = job
        while time.monotonic() < deadline:
            current = services.get_job(job_id) or current
            status = str(current.get("status", "") or "")
            stage = str(current.get("stage", "") or "")
            progress = int(current.get("progress_percent", 0) or 0)
            message = str(current.get("status_message", "") or "")
            line = f"status={status} stage={stage} progress={progress} message={message}"
            if line != last_line:
                print(line, flush=True)
                last_line = line
            if status and status != "running":
                break
            time.sleep(max(args.poll_seconds, 1.0))
        else:
            services.stop_job(job_id)
            current = _wait_for_terminal_job_state(
                services,
                job_id,
                current=current,
                poll_seconds=max(args.poll_seconds / 2.0, 1.0),
                timeout_seconds=max(args.poll_seconds * 3.0, 30.0),
            )

        manifest_path = capture_launcher_replay_manifest(output_root, job_id, persisted_job=current)
        manifest = build_launcher_replay_manifest(output_root, job_id, persisted_job=current)
        reference_manifest = build_launcher_replay_manifest(output_root, SQUARE_REFERENCE_JOB_ID)
        comparison = compare_launcher_replay_manifests(reference_manifest, manifest)
        result = {
            "schema_version": 1,
            "job_id": job_id,
            "generated_at_epoch": time.time(),
            "config_template": str(config_template),
            "scope_file": str(scope_file),
            "manifest_path": str(manifest_path),
            "terminal_status": str(current.get("status", "") or ""),
            "terminal_stage": str(current.get("stage", "") or ""),
            "failure_reason_code": str(current.get("failure_reason_code", "") or ""),
            "failure_reason": str(current.get("failure_reason", "") or ""),
            "warning_count": int(current.get("warning_count", 0) or 0),
            "fatal_signal_count": int(current.get("fatal_signal_count", 0) or 0),
            "degraded_providers": list(current.get("degraded_providers", []) or []),
            "truth_parity": manifest.get("truth_parity", {}),
            "comparison_to_reference": comparison,
        }
        if result_path is not None:
            _write_json(result_path, result)
            print(f"canary_result={result_path}", flush=True)
        print(json.dumps(result, indent=2, sort_keys=True), flush=True)
        if str(current.get("status", "") or "") == "running":
            return 2
        return 0 if not manifest.get("truth_parity", {}).get("mismatched_fields") else 1
    finally:
        services.close_persistence()


if __name__ == "__main__":
    raise SystemExit(main())
