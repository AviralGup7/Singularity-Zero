"""Recovery must replay every PIPELINE_PROGRESS line into stage_progress."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from src.dashboard.job_record_builder import create_job_record
from src.dashboard.job_state import apply_progress
from src.dashboard.registry import PROGRESS_PREFIX, STAGE_LABELS
from src.dashboard.services.query_service_recovery import recover_job_from_launcher


def _progress_line(payload: dict) -> str:
    return PROGRESS_PREFIX + json.dumps(payload)


def _write_launcher(root: Path, job_id: str, lines: list[str]) -> None:
    launcher = root / "_launcher" / job_id
    launcher.mkdir(parents=True)
    (launcher / "config.json").write_text(
        json.dumps(
            {
                "base_url": "https://example.com",
                "target_name": "example.com",
                "mode": "safe",
                "enabled_modules": ["subfinder", "httpx", "nuclei"],
            }
        ),
        encoding="utf-8",
    )
    (launcher / "scope.txt").write_text("example.com\n", encoding="utf-8")
    (launcher / "stdout.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (launcher / "stderr.txt").write_text("", encoding="utf-8")


def test_recovery_rebuilds_full_stage_progress_matching_live_apply() -> None:
    events = [
        {"stage": "subdomains", "status": "running", "percent": 10, "message": "Enumerating"},
        {"stage": "subdomains", "status": "completed", "percent": 20, "message": "Done subdomains"},
        {
            "stage": "live_hosts",
            "status": "ready",
            "percent": 20,
            "message": "Stage ready: live_hosts",
        },
        {"stage": "live_hosts", "status": "running", "percent": 30, "message": "Probing"},
        {"stage": "live_hosts", "status": "completed", "percent": 36, "message": "Done hosts"},
        {"stage": "urls", "status": "completed", "percent": 50, "message": "Done urls"},
        {
            "stage": "waf",
            "status": "skipped",
            "reason": "condition_never_satisfied",
            "message": "Stage skipped",
        },
        {"stage": "passive_scan", "status": "completed", "percent": 70, "message": "Passive done"},
        {"stage": "active_scan", "status": "running", "percent": 80, "message": "Active running"},
        {"stage": "nuclei", "status": "running", "percent": 82, "message": "Nuclei running"},
    ]
    live = create_job_record(
        "job-live",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    for event in events:
        apply_progress(live, event)

    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        _write_launcher(root, "job-rec", [_progress_line(event) for event in events])
        recovered = recover_job_from_launcher(
            output_root=root,
            job_id="job-rec",
            stage_labels=STAGE_LABELS,
            progress_prefix=PROGRESS_PREFIX,
            path_to_output_href=lambda value: value,
        )

    assert recovered is not None
    recovered_progress = recovered["stage_progress"]
    assert recovered_progress["subdomains"]["status"] == "completed"
    assert recovered_progress["live_hosts"]["status"] == "completed"
    assert recovered_progress["urls"]["status"] == "completed"
    assert recovered_progress["waf"]["status"] == "skipped"
    assert recovered_progress["passive_scan"]["status"] == "completed"
    # Process is gone. The last running stage is the failed/interrupted one;
    # siblings that were still running stay skipped, not completed.
    assert recovered_progress["active_scan"]["status"] == "skipped"
    assert recovered_progress["active_scan"]["reason"] == "interrupted"
    assert recovered_progress["nuclei"]["status"] == "error"
    assert recovered["status"] == "failed"
    assert recovered["stage"] == "nuclei"
    assert live["stage_progress"]["waf"]["status"] == "skipped"
    assert live["stage_progress"]["active_scan"]["status"] == "running"


def test_recovery_completed_run_keeps_skipped_and_does_not_complete_unfinished() -> None:
    events = [
        {"stage": "subdomains", "status": "completed", "percent": 20},
        {"stage": "waf", "status": "skipped", "reason": "no_waf", "message": "skipped"},
        {"stage": "reporting", "status": "completed", "percent": 100},
        {"stage": "active_scan", "status": "running", "percent": 40},
    ]
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        lines = [_progress_line(event) for event in events]
        lines.append("Run complete")
        lines.append("Finalizing run")
        lines.append("Run report: /example.com/report.html")
        _write_launcher(root, "job-done", lines)
        recovered = recover_job_from_launcher(
            output_root=root,
            job_id="job-done",
            stage_labels=STAGE_LABELS,
            progress_prefix=PROGRESS_PREFIX,
            path_to_output_href=lambda value: value,
        )
    assert recovered is not None
    assert recovered["status"] == "completed"
    assert recovered["stage_progress"]["waf"]["status"] == "skipped"
    assert recovered["stage_progress"]["subdomains"]["status"] == "completed"
    assert recovered["stage_progress"]["active_scan"]["status"] == "skipped"
    assert recovered["stage_progress"]["active_scan"]["reason"] == "interrupted"
