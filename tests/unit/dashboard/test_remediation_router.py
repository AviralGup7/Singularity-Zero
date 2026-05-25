import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from src.dashboard.fastapi.routers.remediation import get_remediation_plan


class RemediationRouterTests(unittest.TestCase):
    @staticmethod
    def _services(output_root: Path) -> SimpleNamespace:
        def list_targets() -> list[dict[str, Any]]:
            return [
                {"name": d.name}
                for d in output_root.iterdir()
                if d.is_dir() and not d.name.startswith("_")
            ]

        return SimpleNamespace(
            query=SimpleNamespace(output_root=output_root),
            list_targets=list_targets,
        )

    def test_get_remediation_plan_aggregates_findings_successfully(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)

            # Create a mock target directory and run
            target_name = "test-target.com"
            run_dir = output_root / target_name / "20260522-120000"
            run_dir.mkdir(parents=True)

            # Create findings.json with sample findings
            findings = [
                {
                    "id": "f1",
                    "category": "dns_security",
                    "severity": "high",
                    "title": "Missing SPF Record",
                    "description": "The target lacks an SPF record.",
                },
                {
                    "id": "f2",
                    "category": "open_redirect",
                    "severity": "critical",
                    "title": "Open Redirect",
                    "description": "An open redirect exists at /redirect.",
                },
            ]
            (run_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")

            # Create run_summary.json to make it a valid run dir
            run_summary = {
                "generated_at_utc": "2026-05-22T12:00:00Z",
                "total_findings": 2,
                "severity_counts": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
            }
            (run_dir / "run_summary.json").write_text(json.dumps(run_summary), encoding="utf-8")

            # Call the endpoint
            result = asyncio.run(
                get_remediation_plan(
                    request=None,  # type: ignore
                    _auth=None,
                    services=self._services(output_root),
                )
            )

            # Verify the results
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["total_findings"], 2)
            self.assertEqual(result["total_units"], 2)

            units = result["units"]
            # Sorted by severity (critical, high)
            self.assertEqual(units[0]["category"], "open_redirect")
            self.assertEqual(units[0]["severity"], "critical")
            self.assertEqual(units[0]["total_count"], 1)
            self.assertEqual(units[0]["targets"], [target_name])

            self.assertEqual(units[1]["category"], "dns_security")
            self.assertEqual(units[1]["severity"], "high")
            self.assertEqual(units[1]["total_count"], 1)
            self.assertEqual(units[1]["targets"], [target_name])

    def test_get_remediation_plan_deprioritizes_noisy_findings(self) -> None:
        from unittest.mock import MagicMock

        from src.learning.repositories.telemetry_store import TelemetryStore

        original_get_feedback = TelemetryStore.get_feedback_events
        try:
            # Mock 5 false positives for dns_security and 0 for open_redirect
            TelemetryStore.get_feedback_events = MagicMock(
                return_value=[
                    {"finding_category": "dns_security", "was_false_positive": 1},
                    {"finding_category": "dns_security", "was_false_positive": 1},
                    {"finding_category": "dns_security", "was_false_positive": 1},
                    {"finding_category": "dns_security", "was_false_positive": 1},
                    {"finding_category": "dns_security", "was_false_positive": 1},
                ]
            )

            with tempfile.TemporaryDirectory() as temp_dir:
                output_root = Path(temp_dir)

                # Create a mock target directory and run
                target_name = "test-target.com"
                run_dir = output_root / target_name / "20260522-120000"
                run_dir.mkdir(parents=True)

                # Create findings.json with sample findings (both are HIGH severity)
                findings = [
                    {
                        "id": "f1",
                        "category": "dns_security",
                        "severity": "high",
                        "title": "Missing SPF Record",
                        "description": "The target lacks an SPF record.",
                    },
                    {
                        "id": "f2",
                        "category": "open_redirect",
                        "severity": "high",
                        "title": "Open Redirect",
                        "description": "An open redirect exists.",
                    },
                ]
                (run_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
                (run_dir / "run_summary.json").write_text(
                    json.dumps({"generated_at_utc": "2026", "total_findings": 2}), encoding="utf-8"
                )

                # Call the endpoint
                result = asyncio.run(
                    get_remediation_plan(
                        request=None,  # type: ignore
                        _auth=None,
                        services=self._services(output_root),
                    )
                )

                self.assertEqual(result["status"], "ok")
                units = result["units"]

                # Both are high severity, but open_redirect has 0 false positives, and dns_security has 5.
                # So open_redirect should be sorted FIRST (index 0) and dns_security should be SECOND (index 1).
                self.assertEqual(units[0]["category"], "open_redirect")
                self.assertEqual(units[0]["false_positive_count"], 0)
                self.assertEqual(units[1]["category"], "dns_security")
                self.assertEqual(units[1]["false_positive_count"], 5)
        finally:
            TelemetryStore.get_feedback_events = original_get_feedback


if __name__ == "__main__":
    unittest.main()
