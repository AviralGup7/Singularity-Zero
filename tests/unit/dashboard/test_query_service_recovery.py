import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from src.dashboard.registry import PROGRESS_PREFIX
from src.dashboard.services.query_service import DashboardQueryService


class QueryServiceRecoveryTests(unittest.TestCase):
    def _service(self, output_root: Path) -> DashboardQueryService:
        config_template = output_root / "config_template.json"
        config_template.write_text("{}", encoding="utf-8")
        return DashboardQueryService(
            output_root=output_root,
            config_template=config_template,
            lock=threading.Lock(),
            jobs={},
        )

    def test_get_job_recovers_from_launcher_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            launcher_dir = output_root / "_launcher" / "abc123"
            launcher_dir.mkdir(parents=True)

            (launcher_dir / "config.json").write_text(
                json.dumps(
                    {
                        "base_url": "https://example.com",
                        "target_name": "example.com",
                        "mode": "idor",
                    }
                ),
                encoding="utf-8",
            )
            (launcher_dir / "scope.txt").write_text("example.com\n", encoding="utf-8")
            (launcher_dir / "stdout.txt").write_text(
                "Run report: "
                f"{(output_root / 'example.com' / '20260409-000109' / 'report.html')}\n"
                "Dashboard index: "
                f"{(output_root / 'example.com' / 'index.html')}\n"
                "Finalizing run\n"
                "Deduplicated findings: removed 24, remaining 26\n",
                encoding="utf-8",
            )
            (launcher_dir / "stderr.txt").write_text("", encoding="utf-8")

            report_dir = output_root / "example.com" / "20260409-000109"
            report_dir.mkdir(parents=True)
            (report_dir / "report.html").write_text("ok", encoding="utf-8")
            (output_root / "example.com" / "index.html").write_text("ok", encoding="utf-8")

            service = self._service(output_root)
            job = service.get_job("abc123")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["id"], "abc123")
            self.assertEqual(job["status"], "completed")
            self.assertEqual(job["target_href"], "/example.com/index.html")
            telemetry = job.get("progress_telemetry", {})
            self.assertIn("artifact_recovery", telemetry.get("event_triggers", []))

    def test_get_job_returns_none_when_launcher_artifacts_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            service = self._service(output_root)
            self.assertIsNone(service.get_job("missing123"))

    def test_get_job_reconciles_stale_running_job_from_launcher_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            launcher_dir = output_root / "_launcher" / "stale9876"
            launcher_dir.mkdir(parents=True)

            (launcher_dir / "config.json").write_text(
                json.dumps(
                    {
                        "base_url": "https://squareup.com",
                        "target_name": "square.com",
                        "mode": "idor",
                        "enabled_modules": ["httpx", "katana", "nuclei"],
                    }
                ),
                encoding="utf-8",
            )
            (launcher_dir / "scope.txt").write_text("*.square.com\n", encoding="utf-8")
            (launcher_dir / "stdout.txt").write_text(
                "Artifacts written to: "
                f"{(output_root / 'square.com' / '20260409-010617')}\n"
                "Run report: "
                f"{(output_root / 'square.com' / '20260409-010617' / 'report.html')}\n"
                "Dashboard index: "
                f"{(output_root / 'square.com' / 'index.html')}\n"
                "Finalizing run\n"
                "Deduplicated findings: removed 24, remaining 26\n",
                encoding="utf-8",
            )
            (launcher_dir / "stderr.txt").write_text("", encoding="utf-8")

            report_dir = output_root / "square.com" / "20260409-010617"
            report_dir.mkdir(parents=True)
            (report_dir / "report.html").write_text("ok", encoding="utf-8")
            (output_root / "square.com" / "index.html").write_text("ok", encoding="utf-8")
            (output_root / "config_template.json").write_text("{}", encoding="utf-8")

            persisted_status: list[str] = []
            service = DashboardQueryService(
                output_root=output_root,
                config_template=output_root / "config_template.json",
                lock=threading.Lock(),
                jobs={
                    "stale9876": {
                        "id": "stale9876",
                        "base_url": "https://squareup.com",
                        "hostname": "squareup.com",
                        "scope_entries": ["*.square.com"],
                        "enabled_modules": ["httpx", "katana", "nuclei"],
                        "mode": "idor",
                        "target_name": "square.com",
                        "status": "running",
                        "started_at": 1_000.0,
                        "updated_at": 1_010.0,
                        "finished_at": None,
                        "stage": "startup",
                        "stage_label": "Preparing run",
                        "status_message": "Creating config and scope",
                        "progress_percent": 2,
                        "returncode": None,
                        "error": "",
                        "failed_stage": "",
                        "failure_reason_code": "",
                        "failure_step": "",
                        "failure_reason": "",
                        "warnings": [],
                        "execution_options": {},
                        "latest_logs": ["Run queued"],
                        "config_href": "/_launcher/stale9876/config.json",
                        "scope_href": "/_launcher/stale9876/scope.txt",
                        "stdout_href": "/_launcher/stale9876/stdout.txt",
                        "stderr_href": "/_launcher/stale9876/stderr.txt",
                        "target_href": "/square.com/index.html",
                        "stage_progress": {},
                        "progress_telemetry": {
                            "active_task_count": 1,
                            "event_triggers": [],
                            "last_update_epoch": 1_010.0,
                        },
                        "process": None,
                        "stop_requested": False,
                    }
                },
                persist_callback=lambda job: persisted_status.append(str(job.get("status", ""))),
            )

            with patch("src.dashboard.services.query_service.time.time", return_value=1_200.0):
                job = service.get_job("stale9876")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "completed")
            self.assertEqual(job["stage"], "completed")
            self.assertEqual(job["progress_percent"], 100)
            self.assertFalse(job["stalled"])
            self.assertEqual(job["target_href"], "/square.com/index.html")
            self.assertIn("completed", persisted_status)

    def test_get_job_reconciles_stale_terminal_reporting_run(self) -> None:
        class _HungProcess:
            def __init__(self) -> None:
                self.terminated = False

            def poll(self) -> None:
                return None

            def terminate(self) -> None:
                self.terminated = True

        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            process = _HungProcess()
            stale_started_at = 1_000.0
            stale_updated_at = 1_020.0
            reconciled: list[str] = []

            service = DashboardQueryService(
                output_root=output_root,
                config_template=output_root / "config_template.json",
                lock=threading.Lock(),
                jobs={
                    "job-stuck": {
                        "id": "job-stuck",
                        "base_url": "https://example.com",
                        "hostname": "example.com",
                        "scope_entries": ["example.com"],
                        "enabled_modules": ["httpx"],
                        "mode": "idor",
                        "target_name": "example.com",
                        "status": "running",
                        "started_at": stale_started_at,
                        "updated_at": stale_updated_at,
                        "finished_at": None,
                        "stage": "reporting",
                        "stage_label": "Building report",
                        "status_message": "Deduplicated findings: removed 24, remaining 26",
                        "progress_percent": 100,
                        "returncode": None,
                        "error": "",
                        "failed_stage": "",
                        "failure_reason_code": "nuclei_not_on_path",
                        "failure_step": "",
                        "failure_reason": "",
                        "warnings": [],
                        "execution_options": {},
                        "latest_logs": [
                            "Artifacts written to: output/example.com/20260409-010617",
                            "Run report: output/example.com/20260409-010617/report.html",
                            "Dashboard index: output/example.com/index.html",
                            "Finalizing run",
                            "Deduplicated findings: removed 24, remaining 26",
                        ],
                        "config_href": "/_launcher/job-stuck/config.json",
                        "scope_href": "/_launcher/job-stuck/scope.txt",
                        "stdout_href": "/_launcher/job-stuck/stdout.txt",
                        "stderr_href": "/_launcher/job-stuck/stderr.txt",
                        "target_href": "/example.com/index.html",
                        "stage_progress": {
                            "reporting": {
                                "stage": "reporting",
                                "stage_label": "Building report",
                                "status": "running",
                                "processed": 0,
                                "total": None,
                                "percent": 100,
                                "last_event": "Deduplicated findings: removed 24, remaining 26",
                                "started_at": stale_updated_at,
                                "updated_at": stale_updated_at,
                            },
                            "completed": {
                                "stage": "completed",
                                "stage_label": "Completed",
                                "status": "completed",
                                "processed": 0,
                                "total": None,
                                "percent": 100,
                                "last_event": "Run complete",
                                "started_at": stale_updated_at,
                                "updated_at": stale_updated_at,
                            },
                        },
                        "progress_telemetry": {
                            "active_task_count": 1,
                            "targets": {"queued": 4, "scanning": 1, "done": 3},
                            "next_best_action": "Install nuclei binary or disable nuclei module before retrying.",
                            "last_update_epoch": stale_updated_at,
                        },
                        "process": process,
                        "stop_requested": False,
                    }
                },
                persist_callback=lambda job: reconciled.append(str(job.get("status", ""))),
            )
            (output_root / "config_template.json").write_text("{}", encoding="utf-8")

            with patch("src.dashboard.services.query_service.time.time", return_value=1_200.0):
                job = service.get_job("job-stuck")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "completed")
            self.assertEqual(job["stage"], "completed")
            self.assertEqual(job["progress_percent"], 100)
            self.assertFalse(job["stalled"])
            self.assertEqual(job["failure_reason_code"], "")
            self.assertTrue(process.terminated)
            self.assertIn("completed", reconciled)

    def test_get_job_recovers_restart_failed_job_when_artifacts_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            launcher_dir = output_root / "_launcher" / "restart111"
            launcher_dir.mkdir(parents=True)
            (launcher_dir / "config.json").write_text(
                json.dumps(
                    {
                        "base_url": "https://squareup.com",
                        "target_name": "square.com",
                        "mode": "idor",
                    }
                ),
                encoding="utf-8",
            )
            (launcher_dir / "scope.txt").write_text("*.square.com\n", encoding="utf-8")
            (launcher_dir / "stdout.txt").write_text(
                "Artifacts written to: "
                f"{(output_root / 'square.com' / '20260409-010617')}\n"
                "Run report: "
                f"{(output_root / 'square.com' / '20260409-010617' / 'report.html')}\n"
                "Dashboard index: "
                f"{(output_root / 'square.com' / 'index.html')}\n"
                "Finalizing run\n"
                "Deduplicated findings: removed 24, remaining 26\n",
                encoding="utf-8",
            )
            (launcher_dir / "stderr.txt").write_text("", encoding="utf-8")
            report_dir = output_root / "square.com" / "20260409-010617"
            report_dir.mkdir(parents=True)
            (report_dir / "report.html").write_text("ok", encoding="utf-8")
            (output_root / "square.com" / "index.html").write_text("ok", encoding="utf-8")
            (output_root / "config_template.json").write_text("{}", encoding="utf-8")

            service = DashboardQueryService(
                output_root=output_root,
                config_template=output_root / "config_template.json",
                lock=threading.Lock(),
                jobs={
                    "restart111": {
                        "id": "restart111",
                        "base_url": "https://squareup.com",
                        "hostname": "squareup.com",
                        "scope_entries": ["*.square.com"],
                        "enabled_modules": ["httpx"],
                        "mode": "idor",
                        "target_name": "square.com",
                        "status": "failed",
                        "started_at": 1_000.0,
                        "updated_at": 1_050.0,
                        "finished_at": 1_050.0,
                        "stage": "startup",
                        "stage_label": "Preparing run",
                        "status_message": "Job was interrupted by dashboard restart",
                        "progress_percent": 2,
                        "returncode": 1,
                        "error": "Dashboard restarted while job was running",
                        "failed_stage": "startup",
                        "failure_reason_code": "pipeline_restart",
                        "failure_step": "",
                        "failure_reason": "",
                        "warnings": [],
                        "execution_options": {},
                        "latest_logs": ["Run queued"],
                        "config_href": "/_launcher/restart111/config.json",
                        "scope_href": "/_launcher/restart111/scope.txt",
                        "stdout_href": "/_launcher/restart111/stdout.txt",
                        "stderr_href": "/_launcher/restart111/stderr.txt",
                        "target_href": "/square.com/index.html",
                        "stage_progress": {},
                        "progress_telemetry": {},
                        "process": None,
                        "stop_requested": False,
                    }
                },
            )

            with patch("src.dashboard.services.query_service.time.time", return_value=1_220.0):
                job = service.get_job("restart111")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "completed")
            self.assertEqual(job["stage"], "completed")
            self.assertEqual(job["progress_percent"], 100)

    def test_get_job_recovers_interrupted_run_with_last_known_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            launcher_dir = output_root / "_launcher" / "interrupted555"
            launcher_dir.mkdir(parents=True)

            (launcher_dir / "config.json").write_text(
                json.dumps(
                    {
                        "base_url": "https://squareup.com",
                        "target_name": "square.com",
                        "mode": "idor",
                    }
                ),
                encoding="utf-8",
            )
            (launcher_dir / "scope.txt").write_text("*.square.com\n", encoding="utf-8")
            progress_payload = {
                "stage": "live_hosts",
                "status": "running",
                "percent": 37,
                "message": "live-host probing started: 3852 hosts queued",
            }
            (launcher_dir / "stdout.txt").write_text(
                "Entering stage: Live host probing\n"
                + PROGRESS_PREFIX
                + json.dumps(progress_payload)
                + "\n",
                encoding="utf-8",
            )
            (launcher_dir / "stderr.txt").write_text("", encoding="utf-8")

            service = self._service(output_root)
            job = service.get_job("interrupted555")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "failed")
            self.assertEqual(job["stage"], "live_hosts")
            self.assertEqual(job["failed_stage"], "live_hosts")
            self.assertEqual(job["progress_percent"], 37)
            self.assertEqual(job["failure_reason_code"], "pipeline_interrupted")
            self.assertEqual(
                job["failure_step"],
                "src.recon.live_hosts.probe_live_hosts",
            )
            self.assertIn("interrupted", str(job["status_message"]).lower())
            self.assertIn("interrupted", str(job["error"]).lower())

    def test_get_job_treats_warning_only_stderr_as_interrupted_not_exit_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            launcher_dir = output_root / "_launcher" / "warningonly901"
            launcher_dir.mkdir(parents=True)

            (launcher_dir / "config.json").write_text(
                json.dumps(
                    {
                        "base_url": "https://squareup.com",
                        "target_name": "square.com",
                        "mode": "idor",
                    }
                ),
                encoding="utf-8",
            )
            (launcher_dir / "scope.txt").write_text("*.square.com\n", encoding="utf-8")
            progress_payload = {
                "stage": "urls",
                "status": "running",
                "percent": 58,
                "message": "URL provider orchestration still running",
            }
            (launcher_dir / "stdout.txt").write_text(
                PROGRESS_PREFIX + json.dumps(progress_payload) + "\n",
                encoding="utf-8",
            )
            (launcher_dir / "stderr.txt").write_text(
                "Warning: Command '['waybackurls']' timed out after 1 seconds\n",
                encoding="utf-8",
            )

            service = self._service(output_root)
            job = service.get_job("warningonly901")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "failed")
            self.assertEqual(job["stage"], "urls")
            self.assertEqual(job["failed_stage"], "urls")
            self.assertEqual(job["failure_reason_code"], "pipeline_interrupted")
            self.assertNotEqual(job["failure_reason_code"], "pipeline_exit_nonzero")

    def test_get_job_recovers_stage_from_full_progress_history_not_tail_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            launcher_dir = output_root / "_launcher" / "historytail777"
            launcher_dir.mkdir(parents=True)

            (launcher_dir / "config.json").write_text(
                json.dumps(
                    {
                        "base_url": "https://squareup.com",
                        "target_name": "square.com",
                        "mode": "idor",
                    }
                ),
                encoding="utf-8",
            )
            (launcher_dir / "scope.txt").write_text("*.square.com\n", encoding="utf-8")

            live_progress = {
                "stage": "live_hosts",
                "status": "running",
                "percent": 47,
                "message": "Stage finished: Live host probing",
            }
            url_progress = {
                "stage": "urls",
                "status": "running",
                "percent": 50,
                "message": "Entering stage: URL collection",
            }
            warning_lines = "\n".join(
                f"Warning: archive source timeout {idx}" for idx in range(220)
            )
            (launcher_dir / "stdout.txt").write_text(
                PROGRESS_PREFIX
                + json.dumps(live_progress)
                + "\n"
                + PROGRESS_PREFIX
                + json.dumps(url_progress)
                + "\n"
                + warning_lines
                + "\n",
                encoding="utf-8",
            )
            (launcher_dir / "stderr.txt").write_text("", encoding="utf-8")

            service = self._service(output_root)
            job = service.get_job("historytail777")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "failed")
            self.assertEqual(job["stage"], "urls")
            self.assertEqual(job["failed_stage"], "urls")
            self.assertEqual(job["failure_reason_code"], "pipeline_interrupted")
            self.assertEqual(job["failure_step"], "src.recon.urls.collect_urls")

    def test_get_job_prefers_interrupted_over_warning_tail_for_square_like_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            launcher_dir = output_root / "_launcher" / "squaretrace888"
            launcher_dir.mkdir(parents=True)

            (launcher_dir / "config.json").write_text(
                json.dumps(
                    {
                        "base_url": "https://squareup.com",
                        "target_name": "square.com",
                        "mode": "idor",
                    }
                ),
                encoding="utf-8",
            )
            (launcher_dir / "scope.txt").write_text("*.square.com\n", encoding="utf-8")
            progress_payload = {
                "stage": "access_control",
                "status": "running",
                "percent": 92,
                "message": "Entering stage: Access control checks",
            }
            (launcher_dir / "stdout.txt").write_text(
                PROGRESS_PREFIX + json.dumps(progress_payload) + "\n",
                encoding="utf-8",
            )
            (launcher_dir / "stderr.txt").write_text(
                "\n".join(
                    [
                        "TimeoutError exception in shielded future",
                        'File "src/pipeline/services/pipeline_orchestrator/stages/_recon_network.py", line 1, in _run_enrichment_sync',
                        "TimeoutError: Synchronous operation exceeded 118s runtime budget",
                        "Warning: Command ['gau.exe'] timed out after 1 seconds",
                        "Warning: Command ['waybackurls.exe'] timed out after 1 seconds",
                    ]
                ),
                encoding="utf-8",
            )

            service = self._service(output_root)
            job = service.get_job("squaretrace888")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "failed")
            self.assertEqual(job["stage"], "access_control")
            self.assertEqual(job["failed_stage"], "access_control")
            self.assertEqual(job["failure_reason_code"], "pipeline_interrupted")
            self.assertNotEqual(job["failure_reason_code"], "pipeline_exit_nonzero")
            self.assertNotIn("gau.exe", str(job["failure_reason"]).lower())
            self.assertEqual(job["fatal_signal_count"], 0)
            self.assertGreaterEqual(job["warning_count"], 2)
            self.assertIn("gau", job["degraded_providers"])
            self.assertIn("waybackurls", job["degraded_providers"])

    def test_get_job_classifies_full_stderr_not_only_tail(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            launcher_dir = output_root / "_launcher" / "stderrfull999"
            launcher_dir.mkdir(parents=True)

            (launcher_dir / "config.json").write_text(
                json.dumps(
                    {
                        "base_url": "https://squareup.com",
                        "target_name": "square.com",
                        "mode": "idor",
                    }
                ),
                encoding="utf-8",
            )
            (launcher_dir / "scope.txt").write_text("*.square.com\n", encoding="utf-8")
            progress_payload = {
                "stage": "access_control",
                "status": "running",
                "percent": 92,
                "message": "Running automated authorization bypass detection",
            }
            (launcher_dir / "stdout.txt").write_text(
                PROGRESS_PREFIX + json.dumps(progress_payload) + "\n",
                encoding="utf-8",
            )

            stderr_lines = [
                "Warning: Command ['gau.exe'] timed out after 120 seconds",
                "Warning: Command ['waybackurls.exe'] timed out after 120 seconds",
            ]
            stderr_lines.extend(f"Warning: archive source timeout {idx}" for idx in range(48))
            (launcher_dir / "stderr.txt").write_text(
                "\n".join(stderr_lines) + "\n",
                encoding="utf-8",
            )

            service = self._service(output_root)
            job = service.get_job("stderrfull999")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["warning_count"], len(stderr_lines))
            self.assertIn("gau", job["degraded_providers"])
            self.assertIn("waybackurls", job["degraded_providers"])
            self.assertLessEqual(len(job["warnings"]), 10)

    def test_get_job_warning_only_without_progress_message_uses_generic_interrupted_reason(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            launcher_dir = output_root / "_launcher" / "warningnomsg100"
            launcher_dir.mkdir(parents=True)

            (launcher_dir / "config.json").write_text(
                json.dumps(
                    {
                        "base_url": "https://squareup.com",
                        "target_name": "square.com",
                        "mode": "idor",
                    }
                ),
                encoding="utf-8",
            )
            (launcher_dir / "scope.txt").write_text("*.square.com\n", encoding="utf-8")
            progress_payload = {
                "stage": "urls",
                "status": "running",
                "percent": 58,
            }
            (launcher_dir / "stdout.txt").write_text(
                PROGRESS_PREFIX + json.dumps(progress_payload) + "\n",
                encoding="utf-8",
            )
            (launcher_dir / "stderr.txt").write_text(
                "Warning: Command '['waybackurls']' timed out after 1 seconds\n",
                encoding="utf-8",
            )

            service = self._service(output_root)
            job = service.get_job("warningnomsg100")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "failed")
            self.assertEqual(job["failure_reason_code"], "pipeline_interrupted")
            self.assertEqual(
                job["failure_reason"],
                "Pipeline process ended before emitting a terminal completion event.",
            )
            self.assertNotIn("timed out", str(job["failure_reason"]).lower())

    def test_get_job_marks_unrecoverable_stale_running_job_as_stalled_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            (output_root / "config_template.json").write_text("{}", encoding="utf-8")
            persisted_status: list[str] = []
            service = DashboardQueryService(
                output_root=output_root,
                config_template=output_root / "config_template.json",
                lock=threading.Lock(),
                jobs={
                    "stale-no-artifacts": {
                        "id": "stale-no-artifacts",
                        "base_url": "https://squareup.com",
                        "hostname": "squareup.com",
                        "scope_entries": ["*.square.com"],
                        "enabled_modules": ["httpx", "waybackurls"],
                        "mode": "idor",
                        "target_name": "square.com",
                        "status": "running",
                        "started_at": 1_000.0,
                        "updated_at": 1_020.0,
                        "finished_at": None,
                        "stage": "live_hosts",
                        "stage_label": "Live host probing",
                        "status_message": "live-host batch 4/12 running",
                        "progress_percent": 44,
                        "returncode": None,
                        "error": "",
                        "failed_stage": "",
                        "failure_reason_code": "",
                        "failure_step": "",
                        "failure_reason": "",
                        "warnings": [],
                        "execution_options": {},
                        "latest_logs": ["live-host batch 4/12 running"],
                        "config_href": "/_launcher/stale-no-artifacts/config.json",
                        "scope_href": "/_launcher/stale-no-artifacts/scope.txt",
                        "stdout_href": "/_launcher/stale-no-artifacts/stdout.txt",
                        "stderr_href": "/_launcher/stale-no-artifacts/stderr.txt",
                        "target_href": "/square.com/index.html",
                        "stage_progress": {},
                        "progress_telemetry": {
                            "active_task_count": 1,
                            "event_triggers": [],
                            "last_update_epoch": 1_020.0,
                        },
                        "process": None,
                        "stop_requested": False,
                    }
                },
                persist_callback=lambda job: persisted_status.append(str(job.get("status", ""))),
            )

            with patch("src.dashboard.services.query_service.time.time", return_value=1_300.0):
                job = service.get_job("stale-no-artifacts")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "failed")
            self.assertEqual(job["stage"], "live_hosts")
            self.assertEqual(job["failed_stage"], "live_hosts")
            self.assertEqual(job["failure_reason_code"], "stalled_without_terminal_marker")
            self.assertEqual(job["failure_step"], "src.recon.live_hosts.probe_live_hosts")
            self.assertIn(
                "stalled without terminal completion marker", job["status_message"].lower()
            )
            telemetry = job.get("progress_telemetry", {})
            self.assertIn("stalled_without_terminal_marker", telemetry.get("event_triggers", []))
            self.assertIn("failed", persisted_status)

    def test_get_job_recovers_stop_marker_as_stopped_terminal_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            launcher_dir = output_root / "_launcher" / "stopped111"
            launcher_dir.mkdir(parents=True)

            (launcher_dir / "config.json").write_text(
                json.dumps(
                    {
                        "base_url": "https://squareup.com",
                        "target_name": "square.com",
                        "mode": "idor",
                    }
                ),
                encoding="utf-8",
            )
            (launcher_dir / "scope.txt").write_text("*.square.com\n", encoding="utf-8")
            progress_payload = {
                "stage": "live_hosts",
                "status": "running",
                "percent": 44,
                "message": "live-host batch 4/12 running",
            }
            (launcher_dir / "stdout.txt").write_text(
                PROGRESS_PREFIX + json.dumps(progress_payload) + "\n",
                encoding="utf-8",
            )
            (launcher_dir / "stderr.txt").write_text("", encoding="utf-8")
            (launcher_dir / "stop_requested.marker").write_text(
                json.dumps({"requested_at_epoch": 1234.0}) + "\n",
                encoding="utf-8",
            )

            service = self._service(output_root)
            job = service.get_job("stopped111")

            self.assertIsNotNone(job)
            assert job is not None
            self.assertEqual(job["status"], "stopped")
            self.assertEqual(job["stage"], "completed")
            self.assertEqual(job["failure_reason_code"], "")
            self.assertEqual(job["failed_stage"], "")
            self.assertEqual(job["error"], "")
            self.assertIn("stopped", str(job["status_message"]).lower())

    def test_stop_job_writes_stop_marker_artifact(self) -> None:
        class _DummyProcess:
            def __init__(self) -> None:
                self.terminated = False

            def terminate(self) -> None:
                self.terminated = True

        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            job_id = "stopmarker222"
            launcher_dir = output_root / "_launcher" / job_id
            launcher_dir.mkdir(parents=True)
            (output_root / "config_template.json").write_text("{}", encoding="utf-8")
            process = _DummyProcess()

            service = DashboardQueryService(
                output_root=output_root,
                config_template=output_root / "config_template.json",
                lock=threading.Lock(),
                jobs={
                    job_id: {
                        "id": job_id,
                        "base_url": "https://squareup.com",
                        "hostname": "squareup.com",
                        "scope_entries": ["*.square.com"],
                        "enabled_modules": ["httpx"],
                        "mode": "idor",
                        "target_name": "square.com",
                        "status": "running",
                        "started_at": 1_000.0,
                        "updated_at": 1_010.0,
                        "finished_at": None,
                        "stage": "live_hosts",
                        "stage_label": "Live host probing",
                        "status_message": "live-host batch 1/12 running",
                        "progress_percent": 40,
                        "returncode": None,
                        "error": "",
                        "failed_stage": "",
                        "failure_reason_code": "",
                        "failure_step": "",
                        "failure_reason": "",
                        "warnings": [],
                        "execution_options": {},
                        "latest_logs": ["live-host batch 1/12 running"],
                        "config_href": f"/_launcher/{job_id}/config.json",
                        "scope_href": f"/_launcher/{job_id}/scope.txt",
                        "stdout_href": f"/_launcher/{job_id}/stdout.txt",
                        "stderr_href": f"/_launcher/{job_id}/stderr.txt",
                        "target_href": "/square.com/index.html",
                        "stage_progress": {},
                        "progress_telemetry": {
                            "active_task_count": 1,
                            "event_triggers": [],
                            "last_update_epoch": 1_010.0,
                        },
                        "process": process,
                        "stop_requested": False,
                    }
                },
            )

            service.stop_job(job_id)

            marker_path = launcher_dir / "stop_requested.marker"
            self.assertTrue(marker_path.exists())
            self.assertTrue(process.terminated)


if __name__ == "__main__":
    unittest.main()
