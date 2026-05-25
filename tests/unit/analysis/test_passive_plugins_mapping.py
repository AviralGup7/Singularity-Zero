import unittest
from src.analysis.plugins.passive import PASSIVE_PLUGIN_SPECS
from src.analysis.plugins._passive_constants import _PLUGIN_DATA

class TestPassivePluginsMapping(unittest.TestCase):
    def test_no_duplicate_keys_or_labels(self) -> None:
        """Verify that every passive plugin key and label is completely unique."""
        keys = [p.key for p in PASSIVE_PLUGIN_SPECS]
        labels = [p.label for p in PASSIVE_PLUGIN_SPECS]
        
        # Check for duplicate keys
        duplicate_keys = {k for k in keys if keys.count(k) > 1}
        self.assertEqual(len(duplicate_keys), 0, f"Duplicate keys found: {duplicate_keys}")
        
        # Check for duplicate labels
        duplicate_labels = {l for l in labels if labels.count(l) > 1}
        self.assertEqual(len(duplicate_labels), 0, f"Duplicate labels found: {duplicate_labels}")

    def test_exposure_related_plugins_are_mapped(self) -> None:
        """Verify that specific, crucial exposure-related passive scan plugins are mapped."""
        exposure_keys = {p.key for p in PASSIVE_PLUGIN_SPECS if p.group == "exposure"}
        
        expected_keys = {
            "sensitive_data_scanner",
            "header_checker",
            "vulnerable_component_detector",
            "cookie_security_checker",
            "cors_misconfig_checker",
            "cache_control_checker",
            "frontend_config_exposure_checker",
            "directory_listing_checker",
            "debug_artifact_checker",
            "stored_xss_signal_detector",
            "technology_fingerprint",
            "anomaly_detector",
        }
        
        for k in expected_keys:
            self.assertIn(k, exposure_keys, f"Expected exposure plugin '{k}' is missing or not grouped under 'exposure'")

    def test_idor_logic_diff_plugins_are_mapped(self) -> None:
        """Verify that IDOR, logic, and diff-related plugins are correctly mapped without overlapping."""
        idor_keys = {p.key for p in PASSIVE_PLUGIN_SPECS if p.group == "idor"}
        logic_keys = {p.key for p in PASSIVE_PLUGIN_SPECS if p.group == "logic"}
        
        # Verify key IDOR-related plugins
        expected_idor = {
            "idor_candidate_finder",
            "sensitive_field_detector",
            "nested_object_traversal",
            "endpoint_resource_groups",
            "bulk_endpoint_detector",
            "pagination_walker",
            "response_size_anomaly_detector",
            "response_structure_validator",
            "json_response_parser",
            "json_schema_inference",
        }
        for k in expected_idor:
            self.assertIn(k, idor_keys, f"Expected IDOR plugin '{k}' is missing or not grouped under 'idor'")
            
        # Verify key logic-related plugins
        expected_logic = {
            "response_diff_engine",
            "multi_step_flow_breaking_probe",
            "smart_payload_suggestions",
            "filter_parameter_fuzzer",
            "error_based_inference",
            "state_transition_analyzer",
            "parameter_dependency_tracker",
            "flow_integrity_checker",
            "race_condition_signal_analyzer",
            "version_diffing",
            "payment_flow_intelligence",
            "payment_provider_detection",
            "behavior_analysis_layer",
            "server_side_injection_surface_analyzer",
        }
        for k in expected_logic:
            self.assertIn(k, logic_keys, f"Expected logic plugin '{k}' is missing or not grouped under 'logic'")
            
        # Verify specific diff-related plugins exist and are not overlapping (they belong to distinct categories/groups)
        diff_specs = [p for p in PASSIVE_PLUGIN_SPECS if "diff" in p.key or "diff" in p.description.lower()]
        self.assertGreater(len(diff_specs), 0)
        
        # Verify no overlapping keys or duplicate assignments
        diff_keys = [p.key for p in diff_specs]
        self.assertEqual(len(diff_keys), len(set(diff_keys)), f"Duplicate/overlapping diff plugins: {diff_keys}")
        
        # Check specific expected diff plugins:
        expected_diffs = {"response_diff_engine", "version_diffing", "role_context_diff"}
        for k in expected_diffs:
            self.assertIn(k, diff_keys, f"Expected diff-related plugin '{k}' is missing or not identified by diff characteristics")

    def test_matching_constants_data(self) -> None:
        """Verify that PASSIVE_PLUGIN_SPECS matches the length and content of _PLUGIN_DATA exactly."""
        self.assertEqual(len(PASSIVE_PLUGIN_SPECS), len(_PLUGIN_DATA))
        for spec, data in zip(PASSIVE_PLUGIN_SPECS, _PLUGIN_DATA):
            self.assertEqual(spec.key, data[0])
            self.assertEqual(spec.label, data[1])
            self.assertEqual(spec.description, data[2])
            self.assertEqual(spec.group, data[3])
