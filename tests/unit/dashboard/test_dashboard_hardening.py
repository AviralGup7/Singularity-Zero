import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from src.analysis.passive.catalog import PASSIVE_CHECK_NAMES
from src.dashboard.configuration import apply_runtime_overrides, load_template
from src.dashboard.constants import ANALYSIS_CHECK_OPTIONS
from src.dashboard.fastapi.validation import is_within_directory
from src.dashboard.job_store import JobStore
from src.dashboard.pipeline_jobs import create_job_record
from src.dashboard.runtime_controls import RUNTIME_NUMERIC_CONTROLS, NumericControlSpec
from src.dashboard.services import DashboardHandler, DashboardServices
from src.dashboard.utils import build_scope_entries, normalize_base_url, root_domain
from src.pipeline.storage import load_config


class DummyProcess:
    def __init__(self) -> None:
        self.terminated = False
        self.pid = 4242

    def terminate(self) -> None:
        self.terminated = True


class DashboardHardeningTests(unittest.TestCase):
    def test_job_store_save_sanitizes_runtime_process_handle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "jobs.db"
            store = JobStore(db_path)
            try:
                store.save(
                    {
                        "id": "job-process-serialize",
                        "status": "running",
                        "started_at": 1_700_000_000.0,
                        "updated_at": 1_700_000_001.0,
                        "process": DummyProcess(),
                    }
                )
                loaded = store.load_all()["job-process-serialize"]
                self.assertIsNone(loaded.get("process"))
                self.assertEqual(loaded.get("process_pid"), 4242)
            finally:
                local = getattr(store, "_local", None)
                conn = getattr(local, "_conn", None) if local is not None else None
                if conn is not None:
                    conn.close()

    def test_is_within_directory_blocks_prefix_bypass(self) -> None:
        root = Path("C:/workspace/output").resolve()
        sibling = Path("C:/workspace/output-evil/run/behavior_analysis_layer.json").resolve()
        self.assertFalse(is_within_directory(root, sibling))

    def test_is_within_directory_allows_nested_paths(self) -> None:
        root = Path("C:/workspace/output").resolve()
        nested = Path("C:/workspace/output/target/run/behavior_analysis_layer.json").resolve()
        self.assertTrue(is_within_directory(root, nested))

    def test_normalize_base_url_rejects_unsupported_scheme(self) -> None:
        with self.assertRaises(ValueError):
            normalize_base_url("ftp://example.com")

    def test_root_domain_keeps_ip_addresses_and_localhost(self) -> None:
        self.assertEqual(root_domain("127.0.0.1"), "127.0.0.1")
        self.assertEqual(root_domain("localhost"), "localhost")

    def test_build_scope_entries_skips_wildcard_for_ip(self) -> None:
        self.assertEqual(build_scope_entries("127.0.0.1"), ["127.0.0.1"])

    def test_apply_runtime_overrides_validates_bounds(self) -> None:
        config: dict[str, Any] = {
            "filters": {},
            "tools": {},
            "nuclei": {},
            "analysis": {},
            "review": {},
        }
        with self.assertRaises(ValueError):
            apply_runtime_overrides(config, {"priority_limit": "0"})
        with self.assertRaises(ValueError):
            apply_runtime_overrides(config, {"request_rate_per_second": "0"})

    def test_apply_runtime_overrides_reports_parse_errors(self) -> None:
        config: dict[str, Any] = {
            "filters": {},
            "tools": {},
            "nuclei": {},
            "analysis": {},
            "review": {},
        }
        with self.assertRaisesRegex(ValueError, "httpx_threads must be an integer"):
            apply_runtime_overrides(config, {"httpx_threads": "abc"})
        with self.assertRaisesRegex(ValueError, "request_rate_per_second must be a number"):
            apply_runtime_overrides(config, {"request_rate_per_second": "nanx"})

    def test_numeric_control_spec_rejects_invalid_metadata(self) -> None:
        with self.assertRaises(ValueError):
            NumericControlSpec("bad", "Bad", ("analysis", "x"), 1, value_type="decimal")
        with self.assertRaises(ValueError):
            NumericControlSpec("bad", "Bad", ("analysis", "x"), 1, value_type="int", minimum=0.5)
        with self.assertRaises(ValueError):
            NumericControlSpec("bad", "Bad", ("analysis", "x"), 1, value_type="float", step=0)

    def test_load_config_rejects_non_mapping_sections(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            config_path.write_text(
                (
                    '{"target_name":"demo","output_dir":"output","http_timeout_seconds":12,'
                    '"tools":[]}'
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_config(config_path)

    def test_launcher_stop_job_marks_request_and_terminates(self) -> None:
        launcher = DashboardServices(Path("."), Path("."), Path("configs/config.example.json"))
        job = create_job_record(
            "job1",
            "https://example.com",
            "example.com",
            ["example.com"],
            ["httpx"],
            "example.com",
            "idor",
        )
        process = DummyProcess()
        job["process"] = process
        launcher.jobs["job1"] = job

        snapshot = launcher.stop_job("job1")

        self.assertTrue(process.terminated)
        self.assertTrue(launcher.jobs["job1"]["stop_requested"])
        self.assertEqual(snapshot["status_message"], "Stopping run")

    def test_launcher_api_defaults_exposes_runtime_controls(self) -> None:
        launcher = DashboardServices(Path("."), Path("."), Path("configs/config.example.json"))
        defaults = launcher.api_defaults()
        self.assertIn("default_mode", defaults)
        self.assertIn("form_defaults", defaults)
        self.assertIn("httpx_threads", defaults["form_defaults"])
        self.assertIn("refresh_cache", defaults["form_defaults"])
        self.assertIn("auto_max_speed_mode", defaults["form_defaults"])
        self.assertIn("httpx_batch_concurrency", defaults["form_defaults"])
        self.assertIn("httpx_fallback_threads", defaults["form_defaults"])
        self.assertIn("httpx_probe_timeout_seconds", defaults["form_defaults"])
        self.assertIn("pagination_walk_limit", defaults["form_defaults"])
        self.assertIn("options_probe_limit", defaults["form_defaults"])

    def test_restart_job_safe_preserves_cache_friendly_execution_options(self) -> None:
        launcher = DashboardServices(Path("."), Path("."), Path("configs/config.example.json"))
        original = create_job_record(
            "job2",
            "https://example.com",
            "example.com",
            ["example.com"],
            ["httpx", "gau"],
            "example.com",
            "safe",
            execution_options={"refresh_cache": True, "skip_crtsh": False, "dry_run": False},
        )
        original["status"] = "failed"
        launcher.jobs["job2"] = original

        with patch.object(
            launcher.launch,
            "start",
            return_value={
                "id": "newjob",
                "status": "running",
                "execution_options": {"refresh_cache": False, "skip_crtsh": True, "dry_run": False},
            },
        ) as mocked_start:
            restarted = launcher.restart_job_safe("job2")

        _, kwargs = mocked_start.call_args

        self.assertEqual(restarted["status"], "running")
        self.assertTrue(restarted["execution_options"]["skip_crtsh"])
        self.assertFalse(restarted["execution_options"]["refresh_cache"])
        self.assertEqual(kwargs["execution_options"]["skip_crtsh"], True)
        self.assertEqual(kwargs["execution_options"]["refresh_cache"], False)

    def test_dashboard_analysis_controls_cover_passive_catalog(self) -> None:
        option_names = {item["name"] for item in ANALYSIS_CHECK_OPTIONS}
        self.assertSetEqual(option_names, set(PASSIVE_CHECK_NAMES))

    def test_load_template_backfills_analysis_defaults_for_all_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = load_template(Path(temp_dir) / "missing-template.json", Path(temp_dir))
        analysis = config["analysis"]
        for name in PASSIVE_CHECK_NAMES:
            self.assertIn(name, analysis)
        self.assertFalse(analysis["trace_method_probe"])
        self.assertFalse(analysis["auto_max_speed_mode"])

    def test_runtime_numeric_controls_cover_new_probe_limits(self) -> None:
        control_names = {spec.name for spec in RUNTIME_NUMERIC_CONTROLS}
        self.assertIn("parameter_pollution_limit", control_names)
        self.assertIn("auth_header_variation_limit", control_names)
        self.assertIn("json_mutation_limit", control_names)
        self.assertIn("payload_suggestion_limit", control_names)
        self.assertIn("pagination_walk_limit", control_names)
        self.assertIn("filter_fuzzer_limit", control_names)
        self.assertIn("error_inference_limit", control_names)
        self.assertIn("flow_break_limit", control_names)
        self.assertIn("version_diff_limit", control_names)
        self.assertIn("unauth_access_limit", control_names)
        self.assertIn("options_probe_limit", control_names)
        self.assertIn("reflected_xss_probe_limit", control_names)

    def test_json_to_params_preserves_modules_and_flags(self) -> None:
        handler = DashboardHandler.__new__(DashboardHandler)
        params = handler._json_to_params(
            {
                "base_url": "https://example.com",
                "modules": ["httpx", "gau"],
                "refresh_cache": True,
                "analysis_enabled": True,
                "auto_max_speed_mode": True,
                "ai_endpoint_exposure_analyzer": True,
            }
        )
        self.assertEqual(params["modules"], ["httpx", "gau"])
        self.assertEqual(params["refresh_cache"], ["1"])
        self.assertEqual(params["analysis_enabled"], ["1"])
        self.assertEqual(params["auto_max_speed_mode"], ["1"])
        self.assertEqual(params["ai_endpoint_exposure_analyzer"], ["1"])

    def test_init_persistence_loads_stale_jobs_as_failed_in_memory(self) -> None:
        def _close_job_store_connection(store_obj: object) -> None:
            local = getattr(store_obj, "_local", None)
            conn = getattr(local, "_conn", None) if local is not None else None
            if conn is not None:
                conn.close()
                local._conn = None

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_root = root / "output"
            output_root.mkdir(parents=True, exist_ok=True)
            config_template = root / "config_template.json"
            config_template.write_text("{}", encoding="utf-8")

            db_path = output_root / "jobs.db"
            store = JobStore(db_path)
            try:
                store.save(
                    {
                        "id": "stale-run",
                        "base_url": "https://example.com",
                        "hostname": "example.com",
                        "scope_entries": ["example.com"],
                        "enabled_modules": ["httpx"],
                        "mode": "idor",
                        "target_name": "example.com",
                        "status": "running",
                        "started_at": 1_000.0,
                        "updated_at": 1_000.0,
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
                        "config_href": "/_launcher/stale-run/config.json",
                        "scope_href": "/_launcher/stale-run/scope.txt",
                        "stdout_href": "/_launcher/stale-run/stdout.txt",
                        "stderr_href": "/_launcher/stale-run/stderr.txt",
                        "target_href": "/example.com/index.html",
                    }
                )

                services = DashboardServices(root, output_root, config_template)
                services.init_persistence(db_path)

                job = services.get_job("stale-run")
                assert job is not None
                self.assertEqual(job["status"], "failed")
                self.assertIn("interrupted", str(job["status_message"]).lower())
            finally:
                _close_job_store_connection(store)
                services_store = getattr(locals().get("services"), "_job_store", None)
                if services_store is not None:
                    _close_job_store_connection(services_store)

    def test_init_persistence_reconciles_persisted_terminal_truth_from_launcher_artifacts(
        self,
    ) -> None:
        def _close_job_store_connection(store_obj: object) -> None:
            local = getattr(store_obj, "_local", None)
            conn = getattr(local, "_conn", None) if local is not None else None
            if conn is not None:
                conn.close()
                local._conn = None

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_root = root / "output"
            launcher_dir = output_root / "_launcher" / "reconcile123"
            launcher_dir.mkdir(parents=True, exist_ok=True)
            target_dir = output_root / "square.com"
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "index.html").write_text("ok", encoding="utf-8")

            config_template = root / "config_template.json"
            config_template.write_text("{}", encoding="utf-8")
            (launcher_dir / "config.json").write_text(
                (
                    '{"base_url": "https://squareup.com", '
                    '"target_name": "square.com", '
                    '"mode": "idor", '
                    '"enabled_modules": ["httpx", "gau", "waybackurls"]}'
                ),
                encoding="utf-8",
            )
            (launcher_dir / "scope.txt").write_text("*.square.com\n", encoding="utf-8")
            (launcher_dir / "stdout.txt").write_text(
                (
                    'PIPELINE_PROGRESS {"stage": "access_control", "status": "running", '
                    '"percent": 92, "message": "Entering stage: Authorization bypass detection"}\n'
                ),
                encoding="utf-8",
            )
            (launcher_dir / "stderr.txt").write_text(
                "\n".join(
                    [
                        "TimeoutError exception in shielded future",
                        'File "src/pipeline/services/pipeline_orchestrator/stages/_recon_network.py", line 245, in _run_enrichment_sync',
                        "TimeoutError: Synchronous operation exceeded 118s runtime budget",
                        "Warning: Command ['gau.exe'] timed out after 1 seconds",
                        "Warning: Command ['waybackurls.exe'] timed out after 1 seconds",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            db_path = output_root / "jobs.db"
            store = JobStore(db_path)
            try:
                store.save(
                    {
                        "id": "reconcile123",
                        "base_url": "https://squareup.com",
                        "hostname": "squareup.com",
                        "scope_entries": ["*.square.com"],
                        "enabled_modules": ["httpx", "gau", "waybackurls"],
                        "mode": "idor",
                        "target_name": "square.com",
                        "status": "failed",
                        "started_at": 1_000.0,
                        "updated_at": 1_050.0,
                        "finished_at": 1_050.0,
                        "stage": "access_control",
                        "stage_label": "Authorization bypass detection",
                        "status_message": "Pipeline failed (exit code 1)",
                        "progress_percent": 92,
                        "returncode": 1,
                        "error": "Warning: Command ['gau.exe'] timed out after 1 seconds",
                        "failed_stage": "access_control",
                        "failure_reason_code": "pipeline_exit_nonzero",
                        "failure_step": "stage:access_control",
                        "failure_reason": "Warning: Command ['gau.exe'] timed out after 1 seconds",
                        "warnings": [],
                        "stderr_warning_lines": [],
                        "stderr_fatal_lines": [],
                        "timeout_events": [],
                        "degraded_providers": [],
                        "configured_timeout_seconds": None,
                        "effective_timeout_seconds": None,
                        "warning_count": 0,
                        "fatal_signal_count": 1,
                        "execution_options": {},
                        "latest_logs": ["Run queued"],
                        "config_href": "/_launcher/reconcile123/config.json",
                        "scope_href": "/_launcher/reconcile123/scope.txt",
                        "stdout_href": "/_launcher/reconcile123/stdout.txt",
                        "stderr_href": "/_launcher/reconcile123/stderr.txt",
                        "target_href": "/square.com/index.html",
                    }
                )

                services = DashboardServices(root, output_root, config_template)
                services.init_persistence(db_path)

                job = services.get_job("reconcile123")
                assert job is not None
                self.assertEqual(job["status"], "failed")
                self.assertEqual(job["stage"], "access_control")
                self.assertEqual(job["failure_reason_code"], "pipeline_interrupted")
                self.assertEqual(job["fatal_signal_count"], 0)
                self.assertIn("gau", job["degraded_providers"])
                self.assertIn("waybackurls", job["degraded_providers"])
            finally:
                _close_job_store_connection(store)
                services_store = getattr(locals().get("services"), "_job_store", None)
                if services_store is not None:
                    _close_job_store_connection(services_store)

    def test_init_persistence_indexes_launcher_jobs_missing_from_store(self) -> None:
        def _close_job_store_connection(store_obj: object) -> None:
            local = getattr(store_obj, "_local", None)
            conn = getattr(local, "_conn", None) if local is not None else None
            if conn is not None:
                conn.close()
                local._conn = None

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_root = root / "output"
            launcher_dir = output_root / "_launcher" / "orphan123"
            launcher_dir.mkdir(parents=True, exist_ok=True)
            target_dir = output_root / "example.com" / "20260424-120000"
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "report.html").write_text("ok", encoding="utf-8")
            (output_root / "example.com").mkdir(parents=True, exist_ok=True)
            (output_root / "example.com" / "index.html").write_text("ok", encoding="utf-8")

            config_template = root / "config_template.json"
            config_template.write_text("{}", encoding="utf-8")
            (launcher_dir / "config.json").write_text(
                json.dumps(
                    {
                        "base_url": "https://example.com",
                        "target_name": "example.com",
                        "mode": "idor",
                        "enabled_modules": ["httpx"],
                    }
                ),
                encoding="utf-8",
            )
            (launcher_dir / "scope.txt").write_text("example.com\n", encoding="utf-8")
            (launcher_dir / "stdout.txt").write_text(
                "\n".join(
                    [
                        f"Artifacts written to: {target_dir}",
                        f"Run report: {target_dir / 'report.html'}",
                        f"Dashboard index: {output_root / 'example.com' / 'index.html'}",
                        "Finalizing run",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (launcher_dir / "stderr.txt").write_text("", encoding="utf-8")

            db_path = output_root / "jobs.db"
            services = DashboardServices(root, output_root, config_template)
            try:
                services.init_persistence(db_path)

                job = services.get_job("orphan123")
                assert job is not None
                self.assertEqual(job["status"], "completed")
                self.assertEqual(job["stage"], "completed")
                self.assertEqual(job["target_href"], "/example.com/index.html")

                persisted = services._job_store.load_all()
                self.assertIn("orphan123", persisted)
                self.assertEqual(persisted["orphan123"]["status"], "completed")
            finally:
                services_store = getattr(locals().get("services"), "_job_store", None)
                if services_store is not None:
                    _close_job_store_connection(services_store)


if __name__ == "__main__":
    unittest.main()
