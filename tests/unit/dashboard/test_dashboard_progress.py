import unittest
from typing import Any
from unittest.mock import patch

from src.dashboard.job_state import apply_progress, snapshot_job
from src.dashboard.utils import estimate_remaining


class DashboardProgressTests(unittest.TestCase):
    def _job(self) -> dict[str, Any]:
        return {
            "id": "abc123",
            "base_url": "https://example.com",
            "hostname": "example.com",
            "scope_entries": ["example.com"],
            "enabled_modules": ["subfinder"],
            "mode": "safe",
            "target_name": "example.com",
            "status": "running",
            "started_at": 1_000.0,
            "updated_at": 1_000.0,
            "finished_at": None,
            "stage": "startup",
            "stage_label": "Preparing run",
            "status_message": "Loading configuration",
            "progress_percent": 2,
            "returncode": None,
            "error": "",
            "warnings": [],
            "execution_options": {},
            "latest_logs": [],
            "config_href": "/_launcher/abc123/config.json",
            "scope_href": "/_launcher/abc123/scope.txt",
            "stdout_href": "/_launcher/abc123/stdout.txt",
            "stderr_href": "/_launcher/abc123/stderr.txt",
            "target_href": "/example.com/index.html",
            "progress_history": [(1_000.0, 2)],
            "stage_processed": None,
            "stage_total": None,
        }

    def test_apply_progress_is_monotonic(self) -> None:
        job = self._job()
        apply_progress(job, {"stage": "subdomains", "message": "Found subdomains", "percent": 30})
        apply_progress(job, {"stage": "subdomains", "message": "Retrying", "percent": 18})

        self.assertEqual(job["progress_percent"], 30)

    def test_apply_progress_supports_processed_total(self) -> None:
        job = self._job()
        apply_progress(
            job,
            {
                "stage": "live_hosts",
                "message": "batch",
                "processed": 40,
                "total": 100,
            },
        )

        self.assertEqual(job["stage_processed"], 40)
        self.assertEqual(job["stage_total"], 100)
        self.assertGreaterEqual(job["progress_percent"], 36)

    def test_estimate_remaining_uses_history_when_available(self) -> None:
        remaining = estimate_remaining(
            progress_percent=40,
            elapsed_seconds=100,
            progress_history=[(0.0, 10), (100.0, 40)],
        )

        self.assertIsNotNone(remaining)
        self.assertGreater(remaining or 0.0, 0.0)

    def test_snapshot_marks_stalled_when_no_recent_updates(self) -> None:
        job = self._job()
        job["updated_at"] = 0.0

        snap = snapshot_job(job)

        self.assertTrue(snap["stalled"])

    def test_snapshot_includes_ist_labels(self) -> None:
        snap = snapshot_job(self._job())

        self.assertIn("IST", snap["started_at_label"])
        self.assertIn("IST", snap["updated_at_label"])

    @patch("src.dashboard.job_state.time.time", return_value=1_200.0)
    def test_snapshot_round_trip_preserves_updated_at(self, _mock_time: Any) -> None:
        job = self._job()
        job["started_at"] = 1_000.0
        job["updated_at"] = 1_190.0

        first = snapshot_job(job)
        second = snapshot_job(first)

        self.assertFalse(first["stalled"])
        self.assertFalse(second["stalled"])

    def test_non_error_progress_does_not_overwrite_existing_failure_reason(self) -> None:
        job = self._job()
        apply_progress(
            job,
            {
                "stage": "subdomains",
                "status": "error",
                "message": "No subdomains discovered",
                "failed_stage": "subdomains",
                "failure_reason_code": "no_subdomains_discovered",
                "failure_reason": "No subdomains discovered from configured recon tools.",
            },
        )
        apply_progress(
            job,
            {
                "stage": "subdomains",
                "status": "running",
                "message": "Found 0 subdomains",
            },
        )

        self.assertEqual(
            job["failure_reason"], "No subdomains discovered from configured recon tools."
        )
        self.assertEqual(job["failure_reason_code"], "no_subdomains_discovered")

    def test_stage_transition_marks_previous_stage_completed(self) -> None:
        job = self._job()
        apply_progress(
            job, {"stage": "subdomains", "message": "Enumerating subdomains", "percent": 15}
        )
        apply_progress(job, {"stage": "live_hosts", "message": "Probing live hosts", "percent": 36})

        stage_progress = job.get("stage_progress", {})
        self.assertEqual(stage_progress["subdomains"]["status"], "completed")
        self.assertEqual(stage_progress["subdomains"]["percent"], 100)
        self.assertEqual(stage_progress["live_hosts"]["status"], "running")

    def test_running_stage_updates_status_message_for_same_stage_progress(self) -> None:
        job = self._job()
        apply_progress(job, {"stage": "live_hosts", "message": "Probing live hosts", "percent": 36})
        apply_progress(
            job,
            {
                "stage": "live_hosts",
                "status": "running",
                "message": "live-host batch 1/10: total 42 live hosts",
                "processed": 400,
                "total": 3800,
            },
        )

        self.assertIn("batch 1/10", job["status_message"])
        self.assertEqual(job["stage_progress"]["live_hosts"]["percent"], 10)

    def test_stage_percent_can_be_derived_from_overall_percent(self) -> None:
        job = self._job()
        apply_progress(
            job, {"stage": "subdomains", "message": "Enumerating subdomains", "percent": 15}
        )
        apply_progress(job, {"stage": "subdomains", "message": "Found subdomains", "percent": 28})

        stage_percent = int(job["stage_progress"]["subdomains"]["percent"])
        self.assertGreater(stage_percent, 0)

    def test_apply_progress_tracks_skipped_stage_and_reason(self) -> None:
        job = self._job()
        apply_progress(
            job,
            {
                "stage": "nuclei",
                "status": "skipped",
                "message": "Skipping nuclei: executable not found",
                "reason": "nuclei_not_on_path",
            },
        )

        self.assertEqual(job["stage_progress"]["nuclei"]["status"], "skipped")
        self.assertEqual(job["stage_progress"]["nuclei"]["reason"], "nuclei_not_on_path")
        telemetry = job.get("progress_telemetry", {})
        skipped = telemetry.get("skipped_stages", [])
        self.assertIn({"stage": "nuclei", "reason": "nuclei_not_on_path"}, skipped)

    def test_apply_progress_tracks_telemetry_fields(self) -> None:
        job = self._job()
        apply_progress(
            job,
            {
                "stage": "priority",
                "status": "running",
                "message": "Priority ranking in progress",
                "high_value_target_count": 12,
                "vulnerability_likelihood_score": 0.67,
                "drop_off_input": 100,
                "drop_off_kept": 35,
                "drop_off_dropped": 65,
                "retry_count": 2,
                "next_best_action": "Run active scan for top 35 endpoints",
                "event_trigger": "ranked_targets_ready",
            },
        )

        snap = snapshot_job(job)
        telemetry = snap["progress_telemetry"]
        self.assertEqual(telemetry["high_value_target_count"], 12)
        self.assertAlmostEqual(telemetry["vulnerability_likelihood_score"], 0.67, places=2)
        self.assertEqual(telemetry["drop_off"]["input"], 100)
        self.assertEqual(telemetry["drop_off"]["kept"], 35)
        self.assertEqual(telemetry["drop_off"]["dropped"], 65)
        self.assertEqual(telemetry["retry_count"], 2)
        self.assertEqual(telemetry["next_best_action"], "Run active scan for top 35 endpoints")
        self.assertIn("ranked_targets_ready", telemetry["event_triggers"])


if __name__ == "__main__":
    unittest.main()
