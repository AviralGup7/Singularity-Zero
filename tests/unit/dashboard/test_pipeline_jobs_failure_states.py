import io
import json
import sys
import threading
from pathlib import Path
from unittest.mock import patch

from src.dashboard.pipeline_jobs import create_job_record, run_pipeline_job
from src.dashboard.registry import PROGRESS_PREFIX


class _DummyProcess:
    def __init__(self, *, stdout_text: str, stderr_text: str, returncode: int) -> None:
        self.stdout = io.StringIO(stdout_text)
        self.stderr = io.StringIO(stderr_text)
        self._returncode = returncode

    def wait(self) -> int:
        return self._returncode


def _prepare_paths(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    workspace_root = tmp_path
    config_path = tmp_path / "config.json"
    scope_path = tmp_path / "scope.txt"
    stdout_path = tmp_path / "stdout.txt"
    stderr_path = tmp_path / "stderr.txt"
    config_path.write_text("{}", encoding="utf-8")
    scope_path.write_text("example.com\n", encoding="utf-8")
    return workspace_root, config_path, scope_path, stdout_path, stderr_path


def test_run_pipeline_job_no_output_sets_actionable_failure_message(tmp_path: Path) -> None:
    workspace_root, config_path, scope_path, stdout_path, stderr_path = _prepare_paths(tmp_path)
    job = create_job_record(
        "job-no-output",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )

    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text="", stderr_text="", returncode=0),
    ):
        run_pipeline_job(
            workspace_root,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
        )

    assert job["status"] == "failed"
    assert job["failure_reason_code"] == "pipeline_no_output"
    assert "produced no output" in job["status_message"].lower()


def test_run_pipeline_job_preserves_recon_failure_stage_and_reason_details(tmp_path: Path) -> None:
    workspace_root, config_path, scope_path, stdout_path, stderr_path = _prepare_paths(tmp_path)
    job = create_job_record(
        "job-recon-fail",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    failure_text = "URL collection produced only fallback seed URLs and no discovery-source URLs."
    progress_payload = {
        "stage": "urls",
        "message": failure_text,
        "percent": 56,
        "status": "failed",
        "failed_stage": "urls",
        "failure_reason_code": "fallback_only_urls",
        "failure_reason": failure_text,
    }
    stdout_text = PROGRESS_PREFIX + json.dumps(progress_payload) + "\n"
    stderr_text = f"ERROR: Critical recon stage failed (urls, fallback_only_urls): {failure_text}\n"

    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text=stdout_text, stderr_text=stderr_text, returncode=1),
    ):
        run_pipeline_job(
            workspace_root,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
        )

    assert job["status"] == "failed"
    assert job["failed_stage"] == "urls"
    assert job["failure_reason_code"] == "fallback_only_urls"
    assert job["failure_step"] == "src.recon.urls.collect_urls"
    assert "fallback" in str(job["failure_reason"]).lower()
    assert "fallback" in str(job["status_message"]).lower()

    stage_progress = job["stage_progress"]
    assert "urls" in stage_progress
    assert stage_progress["urls"]["status"] == "error"


def test_run_pipeline_job_ignores_progress_json_when_extracting_errors(tmp_path: Path) -> None:
    workspace_root, config_path, scope_path, stdout_path, stderr_path = _prepare_paths(tmp_path)
    job = create_job_record(
        "job-progress-json",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    failure_text = "Pipeline execution was interrupted before completion"
    progress_payload = {
        "stage": "live_hosts",
        "message": failure_text,
        "percent": 37,
        "status": "failed",
        "failed_stage": "live_hosts",
        "failure_reason_code": "pipeline_interrupted",
        "failure_reason": failure_text,
    }
    stdout_text = PROGRESS_PREFIX + json.dumps(progress_payload) + "\n"

    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text=stdout_text, stderr_text="", returncode=1),
    ):
        run_pipeline_job(
            workspace_root,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
        )

    assert job["status"] == "failed"
    assert job["failed_stage"] == "live_hosts"
    assert job["failure_reason_code"] == "pipeline_interrupted"
    assert job["failure_reason"] == failure_text
    assert job["error"] == failure_text
    assert not any(PROGRESS_PREFIX in line for line in job["latest_logs"])


def test_run_pipeline_job_ignores_whitespace_prefixed_progress_lines_in_error_extraction(
    tmp_path: Path,
) -> None:
    workspace_root, config_path, scope_path, stdout_path, stderr_path = _prepare_paths(tmp_path)
    job = create_job_record(
        "job-progress-json-whitespace",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    progress_payload = {
        "stage": "subdomains",
        "message": "Stage finished: Subdomain enumeration",
        "percent": 12,
        "status": "completed",
        "stage_status": "completed",
        "error": "",
    }
    stdout_text = f"  {PROGRESS_PREFIX}{json.dumps(progress_payload)}\n"

    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text=stdout_text, stderr_text="", returncode=1),
    ):
        run_pipeline_job(
            workspace_root,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
        )

    assert job["status"] == "failed"
    assert not str(job["failure_reason"]).startswith(PROGRESS_PREFIX)
    assert str(job["failure_reason"]).startswith("Pipeline exited with code 1")


def test_run_pipeline_job_failed_state_does_not_leave_completed_stage_entry(tmp_path: Path) -> None:
    workspace_root, config_path, scope_path, stdout_path, stderr_path = _prepare_paths(tmp_path)
    job = create_job_record(
        "job-terminal-truth",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    completed_payload = {
        "stage": "completed",
        "message": "Run complete",
        "percent": 100,
        "status": "completed",
        "stage_status": "completed",
    }
    failed_payload = {
        "stage": "recon_validation",
        "message": "Pipeline failed at stage recon_validation: Pipeline finished recon without discoverable URLs.",
        "percent": 0,
        "status": "error",
        "stage_status": "error",
        "failed_stage": "recon_validation",
        "failure_reason_code": "pipeline_stage_failed",
        "failure_reason": "Pipeline finished recon without discoverable URLs.",
        "error": "Pipeline finished recon without discoverable URLs.",
    }
    stdout_text = (
        PROGRESS_PREFIX
        + json.dumps(completed_payload)
        + "\n"
        + PROGRESS_PREFIX
        + json.dumps(failed_payload)
        + "\n"
    )

    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text=stdout_text, stderr_text="", returncode=1),
    ):
        run_pipeline_job(
            workspace_root,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
        )

    assert job["status"] == "failed"
    assert job["failed_stage"] == "recon_validation"
    assert job["stage_progress"]["completed"]["status"] == "error"


def test_run_pipeline_job_warning_only_stderr_becomes_interrupted_not_exit_nonzero(
    tmp_path: Path,
) -> None:
    workspace_root, config_path, scope_path, stdout_path, stderr_path = _prepare_paths(tmp_path)
    job = create_job_record(
        "job-warning-only-stderr",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    progress_payload = {
        "stage": "access_control",
        "message": "Entering stage: Access control checks",
        "percent": 92,
        "status": "running",
    }
    stdout_text = PROGRESS_PREFIX + json.dumps(progress_payload) + "\n"
    stderr_text = "Warning: Command ['gau'] timed out after 1 seconds\n"

    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text=stdout_text, stderr_text=stderr_text, returncode=1),
    ):
        run_pipeline_job(
            workspace_root,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
        )

    assert job["status"] == "failed"
    assert job["failure_reason_code"] == "pipeline_interrupted"
    assert job["failure_reason_code"] != "pipeline_exit_nonzero"
    assert "timed out" not in str(job["failure_reason"]).lower()
    assert job["warning_count"] == 1
    assert job["stderr_warning_lines"] == ["Warning: Command ['gau'] timed out after 1 seconds"]


def test_run_pipeline_job_warning_fields_are_canonicalized_from_stderr_classification(
    tmp_path: Path,
) -> None:
    workspace_root, config_path, scope_path, stdout_path, stderr_path = _prepare_paths(tmp_path)
    job = create_job_record(
        "job-warning-canonical",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    progress_payload = {
        "stage": "urls",
        "message": "URL provider orchestration running",
        "percent": 58,
        "status": "running",
    }
    stdout_text = PROGRESS_PREFIX + json.dumps(progress_payload) + "\n"
    stderr_lines = [f"Warning: archive source timeout {idx}" for idx in range(14)]
    stderr_text = "\n".join(stderr_lines) + "\n"

    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text=stdout_text, stderr_text=stderr_text, returncode=1),
    ):
        run_pipeline_job(
            workspace_root,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
        )

    assert job["warning_count"] == len(stderr_lines)
    assert job["stderr_warning_lines"] == stderr_lines[-10:]
    assert job["warnings"] == job["stderr_warning_lines"]
    assert len(job["warnings"]) == 10


def test_run_pipeline_job_enforces_force_fresh_run_flag(tmp_path: Path) -> None:
    workspace_root, config_path, scope_path, stdout_path, stderr_path = _prepare_paths(tmp_path)
    job = create_job_record(
        "job-force-fresh",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )

    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text="", stderr_text="", returncode=0),
    ) as popen_mock:
        run_pipeline_job(
            workspace_root,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
        )

    command = popen_mock.call_args.args[0]
    assert "--force-fresh-run" in command


def test_run_pipeline_job_uses_launcher_config_scope_runtime_entrypoint(tmp_path: Path) -> None:
    workspace_root, config_path, scope_path, stdout_path, stderr_path = _prepare_paths(tmp_path)
    job = create_job_record(
        "job-production-parity-command",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )

    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text="", stderr_text="", returncode=0),
    ) as popen_mock:
        run_pipeline_job(
            workspace_root,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
        )

    command = popen_mock.call_args.args[0]
    assert command[0] == sys.executable
    assert command[1:3] == ["-m", "src.pipeline.runtime"]
    assert "--config" in command
    assert command[command.index("--config") + 1] == str(config_path)
    assert "--scope" in command
    assert command[command.index("--scope") + 1] == str(scope_path)
    assert "--force-fresh-run" in command


def test_run_pipeline_job_persists_terminal_state(tmp_path: Path) -> None:
    workspace_root, config_path, scope_path, stdout_path, stderr_path = _prepare_paths(tmp_path)
    job = create_job_record(
        "job-persist-terminal",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    persisted_statuses: list[str] = []

    def _persist_callback(current_job: dict[str, object]) -> None:
        persisted_statuses.append(str(current_job.get("status", "")))

    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text="", stderr_text="", returncode=0),
    ):
        run_pipeline_job(
            workspace_root,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
            _persist_callback,
        )

    assert persisted_statuses
    assert persisted_statuses[-1] == str(job["status"])
    assert persisted_statuses[-1] == "failed"


def test_run_pipeline_job_writes_forensic_manifest_for_launcher_jobs(tmp_path: Path) -> None:
    launcher_dir = tmp_path / "_launcher" / "job-forensics"
    launcher_dir.mkdir(parents=True)
    workspace_root = tmp_path
    config_path = launcher_dir / "config.json"
    scope_path = launcher_dir / "scope.txt"
    stdout_path = launcher_dir / "stdout.txt"
    stderr_path = launcher_dir / "stderr.txt"
    config_path.write_text(
        json.dumps(
            {
                "base_url": "https://example.com",
                "target_name": "example.com",
                "mode": "safe",
                "enabled_modules": ["subfinder"],
            }
        ),
        encoding="utf-8",
    )
    scope_path.write_text("example.com\n", encoding="utf-8")
    (tmp_path / "example.com").mkdir(exist_ok=True)
    (tmp_path / "example.com" / "index.html").write_text("ok", encoding="utf-8")

    job = create_job_record(
        "job-forensics",
        "https://example.com",
        "example.com",
        ["example.com"],
        ["subfinder"],
        "example.com",
        "safe",
    )
    progress_payload = {
        "stage": "access_control",
        "message": "Entering stage: Access control checks",
        "percent": 92,
        "status": "running",
    }
    stdout_text = PROGRESS_PREFIX + json.dumps(progress_payload) + "\n"
    stderr_text = "Warning: Command ['gau'] timed out after 1 seconds\n"

    with patch(
        "src.dashboard.pipeline_jobs.subprocess.Popen",
        return_value=_DummyProcess(stdout_text=stdout_text, stderr_text=stderr_text, returncode=1),
    ):
        run_pipeline_job(
            workspace_root,
            job,
            threading.Lock(),
            config_path,
            scope_path,
            stdout_path,
            stderr_path,
        )

    manifest_path = launcher_dir / "forensic_manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["job_id"] == "job-forensics"
    assert manifest["artifact_recovery_truth"]["failure_reason_code"] == "pipeline_interrupted"
    assert manifest["artifact_recovery_truth"]["warning_count"] == 1
