import json
import tempfile
import unittest
from pathlib import Path

from src.dashboard.launcher_forensics import (
    SQUARE_BASELINE_JOB_IDS,
    SQUARE_REFERENCE_JOB_ID,
    build_launcher_replay_manifest,
    build_square_launcher_baseline,
    compare_launcher_replay_manifests,
    compare_truth_sources,
    write_launcher_manifest,
)


class LauncherForensicsTests(unittest.TestCase):
    @staticmethod
    def _repo_output_root() -> Path:
        return Path(__file__).resolve().parents[3] / "src" / "dashboard" / "output"

    def test_square_baseline_jobs_have_expected_recovered_truth(self) -> None:
        output_root = self._repo_output_root()
        expected = {
            "a0b71b8e": ("failed", "access_control", "pipeline_interrupted"),
            "3ed7c0ee": ("failed", "access_control", "pipeline_interrupted"),
            "5e20a0db": ("failed", "access_control", "pipeline_interrupted"),
            "70771cc8": ("failed", "live_hosts", "pipeline_interrupted"),
            "59d5e72d": ("completed", "completed", ""),
        }

        for job_id, (status, stage, reason_code) in expected.items():
            manifest = build_launcher_replay_manifest(output_root, job_id)
            recovered = manifest["artifact_recovery_truth"]
            self.assertEqual(recovered["status"], status, job_id)
            self.assertEqual(recovered["stage"], stage, job_id)
            self.assertEqual(recovered["failure_reason_code"], reason_code, job_id)
            self.assertEqual(recovered["target_href"], "/square.com/index.html", job_id)

    def test_warning_escalation_jobs_recover_warning_degradation_truth(self) -> None:
        output_root = self._repo_output_root()
        for job_id in ("a0b71b8e", "3ed7c0ee", "5e20a0db"):
            manifest = build_launcher_replay_manifest(output_root, job_id)
            parity = manifest["truth_parity"]
            persisted = manifest["persisted_job_truth"]
            recovered = manifest["artifact_recovery_truth"]
            self.assertEqual(recovered["failure_reason_code"], "pipeline_interrupted", job_id)
            self.assertEqual(recovered["fatal_signal_count"], 0, job_id)
            self.assertIn("gau", recovered["degraded_providers"], job_id)
            self.assertIn("waybackurls", recovered["degraded_providers"], job_id)
            if parity["persisted_job_present"]:
                self.assertEqual(persisted["failure_reason_code"], "pipeline_interrupted", job_id)
                self.assertEqual(parity["mismatched_fields"], [], job_id)
                self.assertTrue(parity["warning_set_aligned"], job_id)

    def test_square_reference_job_has_completion_markers_and_analyzer(self) -> None:
        output_root = self._repo_output_root()
        manifest = build_launcher_replay_manifest(output_root, SQUARE_REFERENCE_JOB_ID)

        runtime_truth = manifest["runtime_signal_truth"]
        recovered_truth = manifest["artifact_recovery_truth"]
        output_paths = manifest["output_paths"]
        self.assertTrue(runtime_truth["has_completion_markers"])
        self.assertIn("Artifacts written to:", "\n".join(runtime_truth["completion_markers"]))
        self.assertTrue(output_paths["artifacts_dir"]["exists"])
        self.assertTrue(output_paths["artifacts_dir"]["state_transition_analyzer"]["exists"])
        self.assertEqual(
            recovered_truth["warning_count"],
            runtime_truth["warning_count"],
        )

    def test_square_baseline_catalog_round_trips_to_json(self) -> None:
        output_root = self._repo_output_root()
        baseline = build_square_launcher_baseline(output_root)
        self.assertEqual(baseline["job_ids"], list(SQUARE_BASELINE_JOB_IDS))
        self.assertEqual(baseline["reference_job_id"], SQUARE_REFERENCE_JOB_ID)
        self.assertEqual(
            len(baseline["comparisons_to_reference"]), len(SQUARE_BASELINE_JOB_IDS) - 1
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            destination = Path(temp_dir) / "square-baseline.json"
            write_launcher_manifest(destination, baseline)
            parsed = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(parsed["reference_job_id"], SQUARE_REFERENCE_JOB_ID)
            self.assertEqual(parsed["summary"]["job_count"], len(SQUARE_BASELINE_JOB_IDS))

    def test_square_baseline_comparisons_use_reference_job_as_reference(self) -> None:
        output_root = self._repo_output_root()
        baseline = build_square_launcher_baseline(output_root)

        comparisons_by_candidate = {
            item["candidate_job_id"]: item for item in baseline["comparisons_to_reference"]
        }
        self.assertEqual(
            set(comparisons_by_candidate),
            set(SQUARE_BASELINE_JOB_IDS) - {SQUARE_REFERENCE_JOB_ID},
        )

        warning_escalation = comparisons_by_candidate["a0b71b8e"]
        self.assertEqual(warning_escalation["reference_job_id"], SQUARE_REFERENCE_JOB_ID)
        self.assertLess(warning_escalation["warning_count_delta"], 0)
        self.assertGreater(len(warning_escalation["completion_markers_removed"]), 0)
        self.assertTrue(warning_escalation["state_transition_analyzer_lost"])

    def test_compare_launcher_replay_manifests_reports_missing_completion_markers(self) -> None:
        output_root = self._repo_output_root()
        reference_manifest = build_launcher_replay_manifest(output_root, SQUARE_REFERENCE_JOB_ID)
        candidate_manifest = build_launcher_replay_manifest(output_root, "a0b71b8e")

        comparison = compare_launcher_replay_manifests(reference_manifest, candidate_manifest)

        self.assertEqual(comparison["reference_job_id"], SQUARE_REFERENCE_JOB_ID)
        self.assertEqual(comparison["candidate_job_id"], "a0b71b8e")
        self.assertEqual(comparison["completion_markers_added"], [])
        self.assertGreater(len(comparison["completion_markers_removed"]), 0)
        self.assertFalse(comparison["state_transition_analyzer_gained"])
        self.assertTrue(comparison["state_transition_analyzer_lost"])

    def test_compare_truth_sources_flags_warning_set_drift(self) -> None:
        recovered = {
            "status": "failed",
            "stage": "urls",
            "failed_stage": "urls",
            "failure_reason_code": "pipeline_interrupted",
            "failure_reason": "Run interrupted",
            "warning_count": 2,
            "fatal_signal_count": 0,
            "target_href": "/square.com/index.html",
            "warnings": ["Warning: archive timeout 1", "Warning: archive timeout 2"],
        }
        persisted = {
            "status": "failed",
            "stage": "urls",
            "failed_stage": "urls",
            "failure_reason_code": "pipeline_interrupted",
            "failure_reason": "Run interrupted",
            "warning_count": 2,
            "fatal_signal_count": 0,
            "target_href": "/square.com/index.html",
            "warnings": ["Warning: archive timeout 1", "Warning: archive timeout 3"],
        }

        parity = compare_truth_sources(recovered, persisted)

        self.assertTrue(parity["persisted_job_present"])
        self.assertFalse(parity["warning_set_aligned"])
        self.assertIn("warnings", parity["mismatched_fields"])


if __name__ == "__main__":
    unittest.main()
