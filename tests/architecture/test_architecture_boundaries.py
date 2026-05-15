import unittest
from pathlib import Path

from src.analysis.plugin_runtime import ANALYZER_BINDINGS
from src.analysis.plugins import ANALYSIS_PLUGIN_SPECS
from src.api_tests.apitester import get_workflow_runner, list_workflows
from src.api_tests.apitester.result_view import build_result_view
from src.dashboard.services import DashboardServices
from src.detection.registry import DETECTION_PLUGINS_BY_KEY, list_detection_plugins
from src.pipeline.services.pipeline_flow import pipeline_flow_manifest


class ArchitectureBoundaryTests(unittest.TestCase):
    def test_react_ui_build_exists(self) -> None:
        """Verify the React UI production build exists."""
        workspace_root = Path(__file__).resolve().parents[2]
        react_index = workspace_root / "frontend" / "dist" / "index.html"
        self.assertTrue(react_index.exists(), f"React build index.html not found at {react_index}")

    def test_dashboard_services_facade_exposes_query_and_launch_layers(self) -> None:
        workspace_root = Path(__file__).resolve().parents[2]
        services = DashboardServices(
            workspace_root, workspace_root, workspace_root / "configs/config.example.json"
        )

        self.assertEqual(services.form_defaults(), services.query.form_defaults())
        self.assertEqual(services.default_mode_name(), services.query.default_mode_name())
        self.assertEqual(
            services.api_defaults()["default_mode"], services.query.api_defaults()["default_mode"]
        )

    def test_every_analysis_plugin_spec_has_a_registered_binding(self) -> None:
        spec_keys = {spec.key for spec in ANALYSIS_PLUGIN_SPECS}
        self.assertSetEqual(spec_keys, set(ANALYZER_BINDINGS))
        self.assertEqual(ANALYZER_BINDINGS["header_checker"].input_kind, "header_targets_and_cache")
        self.assertEqual(
            ANALYZER_BINDINGS["response_diff_engine"].input_kind, "priority_urls_and_cache"
        )

    def test_api_key_workflow_registry_lists_expected_workflows(self) -> None:
        workflow_keys = [spec.key for spec in list_workflows()]

        self.assertEqual(workflow_keys, ["advanced", "detailed", "scope", "write_actions"])
        self.assertTrue(callable(get_workflow_runner("advanced")))
        self.assertTrue(callable(get_workflow_runner("write_actions")))

    def test_detection_registry_is_unified_with_analysis_plugin_specs(self) -> None:
        spec_keys = {spec.key for spec in ANALYSIS_PLUGIN_SPECS}
        registry_keys = {plugin.key for plugin in list_detection_plugins()}
        self.assertSetEqual(spec_keys, registry_keys)
        self.assertEqual(
            DETECTION_PLUGINS_BY_KEY["header_checker"].input_kind, "header_targets_and_cache"
        )

    def test_pipeline_flow_manifest_is_visible_and_ordered(self) -> None:
        flow = pipeline_flow_manifest()
        self.assertGreaterEqual(len(flow), 8)
        self.assertEqual(flow[0]["key"], "startup")
        self.assertEqual(flow[-1]["key"], "reporting")
        self.assertLessEqual(flow[0]["percent_start"], flow[0]["percent_end"])
        self.assertLessEqual(flow[-1]["percent_start"], flow[-1]["percent_end"])

    def test_result_view_normalizes_scan_data_before_formatting(self) -> None:
        result_view = build_result_view(
            {
                "title": "Potential IDOR",
                "request_context": {
                    "baseline_url": "https://api.example.com/users/123",
                    "mutated_url": "https://api.example.com/users/456",
                    "parameter": "user_id",
                    "variant": "456",
                    "method": "GET",
                },
                "evidence": {
                    "diff_summary": {
                        "status_changed": False,
                        "redirect_changed": False,
                        "content_changed": True,
                        "body_similarity": 0.91,
                        "length_delta": 18,
                    }
                },
            }
        )

        self.assertEqual(result_view["baseline_url"], "https://api.example.com/users/123")
        self.assertEqual(result_view["variant_url"], "https://api.example.com/users/456")
        self.assertEqual(result_view["parameter"], "user_id")
        self.assertEqual(result_view["variant"], "456")
        self.assertEqual(result_view["content_changed"], "yes")


if __name__ == "__main__":
    unittest.main()
