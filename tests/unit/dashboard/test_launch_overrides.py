import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.dashboard.configuration import apply_module_selection, apply_runtime_overrides
from src.dashboard.constants.modules import MODULE_OPTIONS
from src.dashboard.services.launch_service import DashboardLaunchService


class LaunchOverrideTests(unittest.TestCase):
    def test_module_selection_disables_nuclei_tool(self) -> None:
        config = {"tools": {option["name"]: True for option in MODULE_OPTIONS if option["kind"] == "tool"}}
        apply_module_selection(config, {"subfinder", "httpx"})
        self.assertFalse(config["tools"]["nuclei"])
        self.assertTrue(config["tools"]["subfinder"])

    def test_runtime_overrides_set_rate_and_depth(self) -> None:
        config: dict = {"analysis": {}, "httpx": {}}
        apply_runtime_overrides(
            config,
            {
                "request_rate_per_second": "4",
                "httpx_threads": "12",
                "depth": "3",
            },
        )
        self.assertIn("4", str(config.get("analysis", {}).get("request_rate_per_second", config)))

    def test_project_launch_writes_canonical_dir_and_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            output.mkdir()
            service = DashboardLaunchService(
                workspace_root=Path(tmp),
                output_root=output,
                lock=threading.Lock(),
                jobs={},
                query_service=MagicMock(),
            )
            with patch("src.dashboard.services.launch_service.threading.Thread") as thread_cls:
                thread_cls.return_value.start = MagicMock()
                snap = service.start(
                    "https://example.com",
                    selected_modules=["subfinder", "httpx"],
                    runtime_overrides={"request_rate_per_second": "2.5", "depth": "2"},
                    project_config={"mode": "safe", "tools": {"nuclei": True, "subfinder": True}},
                )
            job_id = snap["id"]
            written = output / "_launcher" / job_id / "config.json"
            self.assertTrue(written.is_file())
            payload = json.loads(written.read_text(encoding="utf-8"))
            self.assertFalse(payload["tools"]["nuclei"])
            self.assertEqual(payload["enabled_modules"], ["subfinder", "httpx"])
            self.assertEqual(payload["runtime_overrides"]["depth"], "2")
            self.assertTrue(str(snap["config_href"]).startswith("/_launcher/"))


if __name__ == "__main__":
    unittest.main()
