import json
import tempfile
import threading
import unittest
from pathlib import Path

from src.dashboard.services.query_service import DashboardQueryService


class QueryServiceGapTests(unittest.TestCase):
    def _service(self, output_root: Path) -> DashboardQueryService:
        config_template = output_root / "config_template.json"
        config_template.write_text("{}", encoding="utf-8")
        return DashboardQueryService(
            output_root=output_root,
            config_template=config_template,
            lock=threading.Lock(),
            jobs={},
        )

    def test_detection_gap_summary_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)

            # Target A: has runs
            target_a = "target-a.com"
            run_a1 = output_root / target_a / "20260522-100000"
            run_a1.mkdir(parents=True)
            run_summary_a = {
                "generated_at_utc": "2026-05-22T10:00:00Z",
                "detection_coverage": {
                    "active_modules": ["ssrf_candidate_finder", "reflected_xss_probe"],
                    "empty_modules": ["idor_validation"],
                    "coverage_by_category": {"ssrf": 1, "xss": 1},
                },
            }
            (run_a1 / "run_summary.json").write_text(json.dumps(run_summary_a), encoding="utf-8")

            # Target B: has runs
            target_b = "target-b.com"
            run_b1 = output_root / target_b / "20260522-110000"
            run_b1.mkdir(parents=True)
            run_summary_b = {
                "generated_at_utc": "2026-05-22T11:00:00Z",
                "detection_coverage": {
                    "active_modules": ["idor_validation"],
                    "empty_modules": ["token_leak"],
                    "coverage_by_category": {"idor": 1, "token_leak": 0},
                },
            }
            (run_b1 / "run_summary.json").write_text(json.dumps(run_summary_b), encoding="utf-8")

            service = self._service(output_root)

            # Test aggregating all targets
            all_summary = service.detection_gap_summary()
            self.assertEqual(
                all_summary["active_modules"],
                ["idor_validation", "reflected_xss_probe", "ssrf_candidate_finder"],
            )
            # idor_validation is active in B, so it should be removed from empty modules (which had it in A)
            # empty_modules = sorted(empty_modules - active_modules) = ["token_leak"]
            self.assertEqual(all_summary["empty_modules"], ["token_leak"])
            self.assertEqual(
                all_summary["coverage_by_category"],
                {"ssrf": 1, "xss": 1, "idor": 1, "token_leak": 0},
            )

            # Test querying a single target A
            a_summary = service.detection_gap_summary("target-a.com")
            self.assertEqual(
                a_summary["active_modules"], ["reflected_xss_probe", "ssrf_candidate_finder"]
            )
            self.assertEqual(a_summary["empty_modules"], ["idor_validation"])
            self.assertEqual(a_summary["coverage_by_category"], {"ssrf": 1, "xss": 1})

    def test_detection_gap_summary_fallback_to_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)

            target = "fallback.org"
            run_dir = output_root / target / "20260522-120000"
            run_dir.mkdir(parents=True)

            # run_summary.json lacks "detection_coverage" but has "counts"
            run_summary = {
                "generated_at_utc": "2026-05-22T12:00:00Z",
                "counts": {
                    "scope_entries": 10,  # should be ignored
                    "live_hosts": 5,  # should be ignored
                    "ssrf_candidate_finder": 2,  # >0 -> active
                    "reflected_xss_probe": 0,  # <=0 -> empty
                    "idor_validation": 1,  # >0 -> active
                },
            }
            (run_dir / "run_summary.json").write_text(json.dumps(run_summary), encoding="utf-8")

            service = self._service(output_root)
            summary = service.detection_gap_summary(target)

            self.assertEqual(
                summary["active_modules"], ["idor_validation", "ssrf_candidate_finder"]
            )
            self.assertEqual(summary["empty_modules"], ["reflected_xss_probe"])

    def test_detection_gap_summary_graceful_error_handling(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)

            # Target with malformed run_summary.json
            target_malformed = "malformed.net"
            run_dir = output_root / target_malformed / "20260522-130000"
            run_dir.mkdir(parents=True)
            (run_dir / "run_summary.json").write_text("{invalid json", encoding="utf-8")

            # Target with working run_summary.json
            target_ok = "ok.net"
            run_dir_ok = output_root / target_ok / "20260522-140000"
            run_dir_ok.mkdir(parents=True)
            run_summary_ok = {
                "generated_at_utc": "2026-05-22T14:00:00Z",
                "detection_coverage": {
                    "active_modules": ["ssrf_candidate_finder"],
                    "empty_modules": [],
                    "coverage_by_category": {},
                },
            }
            (run_dir_ok / "run_summary.json").write_text(
                json.dumps(run_summary_ok), encoding="utf-8"
            )

            service = self._service(output_root)
            summary = service.detection_gap_summary()

            # The malformed target should be gracefully skipped without crashing the whole function
            self.assertEqual(summary["active_modules"], ["ssrf_candidate_finder"])
            self.assertEqual(summary["empty_modules"], [])


if __name__ == "__main__":
    unittest.main()
