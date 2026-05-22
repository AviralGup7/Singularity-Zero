import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from src.dashboard.fastapi.routers.remediation import get_remediation_plan


class RemediationRouterTests(unittest.TestCase):
    @staticmethod
    def _services(output_root: Path) -> SimpleNamespace:
        def list_targets() -> list[dict[str, Any]]:
            return [{"name": d.name} for d in output_root.iterdir() if d.is_dir() and not d.name.startswith("_")]
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
                    "description": "The target lacks an SPF record."
                },
                {
                    "id": "f2",
                    "category": "open_redirect",
                    "severity": "critical",
                    "title": "Open Redirect",
                    "description": "An open redirect exists at /redirect."
                }
            ]
            (run_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")

            # Create run_summary.json to make it a valid run dir
            run_summary = {
                "generated_at_utc": "2026-05-22T12:00:00Z",
                "total_findings": 2,
                "severity_counts": {
                    "critical": 1,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
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


if __name__ == "__main__":
    unittest.main()
