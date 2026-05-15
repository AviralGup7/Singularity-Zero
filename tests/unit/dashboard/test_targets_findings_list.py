import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from src.dashboard.fastapi.routers.targets import list_all_findings


class TargetsFindingsListTests(unittest.TestCase):
    @staticmethod
    def _services(output_root: Path) -> SimpleNamespace:
        return SimpleNamespace(query=SimpleNamespace(output_root=output_root))

    def test_list_all_findings_falls_back_to_top_actionable_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            run_dir = output_root / "square.com" / "20260409-010617"
            run_dir.mkdir(parents=True)

            (run_dir / "findings.json").write_text("[]", encoding="utf-8")
            (run_dir / "run_summary.json").write_text(
                json.dumps(
                    {
                        "generated_at_utc": "2026-04-09T01:21:08Z",
                        "top_actionable_findings": [
                            {
                                "title": "DNS security issue: missing_spf_record",
                                "severity": "high",
                                "category": "dns_security",
                                "url": "dns:square.com",
                            },
                            {
                                "title": "Open redirect candidate",
                                "severity": "medium",
                                "category": "open_redirect",
                                "url": "https://square.com/redirect?next=/",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = asyncio.run(
                list_all_findings(
                    page=1,
                    page_size=50,
                    severity=None,
                    target=None,
                    _auth=None,
                    services=self._services(output_root),
                )
            )

            self.assertEqual(result["total"], 2)
            self.assertEqual(len(result["findings"]), 2)
            first = result["findings"][0]
            self.assertEqual(first["target"], "square.com")
            self.assertEqual(first["status"], "open")
            self.assertIn(first["severity"], {"high", "medium"})
            self.assertTrue(str(first.get("id", "")).strip())
            self.assertTrue(str(first.get("type", "")).strip())
            self.assertTrue(str(first.get("date", "")).strip())

    def test_list_all_findings_prefers_findings_json_and_filters(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            run_dir = output_root / "square.com" / "20260409-020000"
            run_dir.mkdir(parents=True)

            (run_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "finding-1",
                            "severity": "critical",
                            "type": "header_checker",
                            "target": "square.com",
                            "status": "open",
                            "date": "2026-04-09T02:00:00Z",
                            "description": "Missing security header",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (run_dir / "run_summary.json").write_text(
                json.dumps(
                    {
                        "top_actionable_findings": [
                            {
                                "title": "Should not be used when findings.json exists",
                                "severity": "low",
                                "category": "test",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = asyncio.run(
                list_all_findings(
                    page=1,
                    page_size=50,
                    severity="critical",
                    target="SQUARE.COM",
                    _auth=None,
                    services=self._services(output_root),
                )
            )

            self.assertEqual(result["total"], 1)
            finding = result["findings"][0]
            self.assertEqual(finding["id"], "finding-1")
            self.assertEqual(finding["severity"], "critical")
            self.assertEqual(finding["type"], "header_checker")
            self.assertEqual(finding["target"], "square.com")


if __name__ == "__main__":
    unittest.main()
