import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from src.dashboard.fastapi.routers.cockpit import (
    get_cockpit_events,
    get_cockpit_graph,
    get_forensic_exchange,
)


class CockpitApiTests(unittest.TestCase):
    @staticmethod
    def _services(output_root: Path) -> SimpleNamespace:
        return SimpleNamespace(query=SimpleNamespace(output_root=output_root))

    def test_get_cockpit_graph_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            target = "test-target"
            run_name = "20260409-010000"
            run_dir = output_root / target / run_name
            run_dir.mkdir(parents=True)

            (run_dir / "urls.txt").write_text(
                "https://example.com/api\nhttps://example.com/admin", encoding="utf-8"
            )
            (run_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "finding-1",
                            "title": "SQL Injection",
                            "severity": "high",
                            "url": "https://example.com/api",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (run_dir / "run_summary.json").write_text(
                json.dumps({"job_id": "job-123"}), encoding="utf-8"
            )

            result = asyncio.run(
                get_cockpit_graph(
                    target=target, run=run_name, _auth=None, services=self._services(output_root)
                )
            )

            self.assertEqual(len(result["nodes"]), 3)  # 2 urls + 1 finding
            self.assertEqual(len(result["edges"]), 1)
            self.assertEqual(result["metadata"]["target"], target)
            self.assertEqual(result["metadata"]["run"], run_name)

    def test_get_cockpit_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            target = "test-target"

            # Mock get_timeline_data
            query_service = SimpleNamespace(
                output_root=output_root,
                get_timeline_data=lambda t: [
                    {
                        "finding_id": "f1",
                        "timestamp": "2026-04-09T01:00:00Z",
                        "severity": "high",
                        "title": "F1",
                    }
                ],
            )
            services = SimpleNamespace(query=query_service)

            # No notes for now
            result = asyncio.run(get_cockpit_events(target=target, _auth=None, services=services))

            self.assertEqual(len(result["events"]), 1)
            self.assertEqual(result["events"][0]["type"], "finding")

    def test_get_forensic_exchange_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir)
            from fastapi import HTTPException

            with self.assertRaises(HTTPException) as cm:
                asyncio.run(
                    get_forensic_exchange(
                        exchange_id="missing",
                        target="test-target",
                        _auth=None,
                        services=self._services(output_root),
                    )
                )
            self.assertEqual(cm.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
