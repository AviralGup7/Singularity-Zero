"""Unfinished running stages must not be rewritten to completed."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from unittest.mock import patch

from src.dashboard.job_state import apply_progress, snapshot_job
from src.dashboard.job_state_helpers import finalize_unfinished_stage_entries
from src.dashboard.pipeline_jobs import create_job_record, run_pipeline_job
from src.dashboard.registry import PROGRESS_PREFIX


def test_finalize_unfinished_does_not_complete_running_stages() -> None:
    progress = {
        "active_scan": {"stage": "active_scan", "status": "running", "percent": 40},
        "nuclei": {"stage": "nuclei", "status": "completed", "percent": 100},
    }
    finalize_unfinished_stage_entries(progress, now=10.0, status="skipped", reason="interrupted")
    assert progress["active_scan"]["status"] == "skipped"
    assert progress["active_scan"]["reason"] == "interrupted"
    assert progress["nuclei"]["status"] == "completed"


def test_apply_progress_keeps_ready_distinct() -> None:
    job = create_job_record(
        "job-ready",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    apply_progress(
        job,
        {
            "stage": "live_hosts",
            "status": "ready",
            "message": "Stage ready: live_hosts",
        },
    )
    assert job["stage_progress"]["live_hosts"]["status"] == "ready"
    snap = snapshot_job(job)
    live = next(item for item in snap["stage_progress"] if item["stage"] == "live_hosts")
    assert live["status"] == "ready"
    assert "running_stages" in snap
    assert "stage_graph" in snap


def test_apply_progress_preserves_injected_and_finished_at() -> None:
    job = create_job_record(
        "job-inject",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    apply_progress(
        job,
        {
            "stage": "threat_modeling",
            "status": "pending",
            "injected": True,
            "message": "Planner injected stage",
        },
    )
    apply_progress(
        job,
        {
            "stage": "threat_modeling",
            "status": "skipped",
            "reason": "planner_dropped",
            "message": "Stage skipped: planner_dropped",
        },
    )
    entry = job["stage_progress"]["threat_modeling"]
    assert entry["injected"] is True
    assert entry["status"] == "skipped"
    assert entry.get("finished_at")
    snap = snapshot_job(job)
    serialized = next(item for item in snap["stage_progress"] if item["stage"] == "threat_modeling")
    assert serialized["injected"] is True
    assert serialized["finished_at"]


class _DummyProcess:
    def __init__(self, stdout_text: str, returncode: int) -> None:
        import io

        self.stdout = io.StringIO(stdout_text)
        self.stderr = io.StringIO("")
        self._returncode = returncode

    def wait(self) -> int:
        return self._returncode


def test_run_pipeline_job_stop_does_not_complete_running_stage(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    scope_path = tmp_path / "scope.txt"
    stdout_path = tmp_path / "stdout.txt"
    stderr_path = tmp_path / "stderr.txt"
    config_path.write_text("{}", encoding="utf-8")
    scope_path.write_text("example.com\n", encoding="utf-8")
    job = create_job_record(
        "job-stop-truth",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    job["stop_requested"] = True
    payload = {
        "stage": "active_scan",
        "status": "running",
        "message": "Active scan running",
        "percent": 40,
    }
    stdout_text = PROGRESS_PREFIX + json.dumps(payload) + "\n"
    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text, 0),
    ):
        run_pipeline_job(
            tmp_path,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
        )
    assert job["status"] == "stopped"
    assert job["stage_progress"]["active_scan"]["status"] == "skipped"
    assert job["stage_progress"]["active_scan"]["reason"] == "job_stopped"


def test_run_pipeline_job_failure_does_not_complete_sibling_running_stage(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    scope_path = tmp_path / "scope.txt"
    stdout_path = tmp_path / "stdout.txt"
    stderr_path = tmp_path / "stderr.txt"
    config_path.write_text("{}", encoding="utf-8")
    scope_path.write_text("example.com\n", encoding="utf-8")
    job = create_job_record(
        "job-fail-parallel",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    stdout_text = (
        PROGRESS_PREFIX
        + json.dumps({"stage": "active_scan", "status": "running", "percent": 20})
        + "\n"
        + PROGRESS_PREFIX
        + json.dumps(
            {
                "stage": "nuclei",
                "status": "error",
                "failed_stage": "nuclei",
                "failure_reason": "template error",
                "message": "nuclei failed",
            }
        )
        + "\n"
    )
    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text, 1),
    ):
        run_pipeline_job(
            tmp_path,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
        )
    assert job["status"] == "failed"
    assert job["stage_progress"]["nuclei"]["status"] == "error"
    assert job["stage_progress"]["active_scan"]["status"] == "skipped"
    assert job["stage_progress"]["active_scan"]["status"] != "completed"
