import unittest
from typing import Any
from unittest.mock import patch

from src.execution.validators.runtime import execute_validation_runtime


class ValidationEngineTests(unittest.TestCase):
    def test_engine_returns_shared_schema_across_validators(self) -> None:
        analysis_results = {
            "ssrf_candidate_finder": [
                {
                    "url": "https://app.example.com/fetch?url=http://169.254.169.254",
                    "score": 8,
                    "signals": ["internal_host_reference:url"],
                    "parameters": ["url"],
                }
            ],
            "idor_candidate_finder": [
                {
                    "url": "https://app.example.com/api/users?id=100",
                    "score": 7,
                    "signals": ["numeric_query_identifier:id"],
                    "query_keys": ["id"],
                    "has_numeric_identifier": True,
                    "comparison": {},
                }
            ],
            "token_leak_detector": [
                {
                    "url": "https://app.example.com/api/session?access_token=abc",
                    "endpoint_key": "session",
                    "location": "query_parameter",
                    "indicators": ["access_token"],
                    "token_shapes": ["generic"],
                    "leak_count": 1,
                    "repeat_count": 1,
                }
            ],
            "behavior_analysis_layer": [],
        }
        ranked_priority_urls = [
            {
                "url": "https://app.example.com/continue?next=https://external.example.net/callback",
                "score": 5,
            }
        ]
        runtime_inputs = {
            "urls": [
                "https://app.example.com/",
                "https://app.example.com/continue?next=https://external.example.net/callback",
            ],
            "responses": [],
        }
        validation_settings = {
            "blackbox_validation": {
                "active_probe_enabled": False,
            }
        }

        if True:
            summary = execute_validation_runtime(
                analysis_results,
                ranked_priority_urls,
                validation_settings,
                runtime_inputs=runtime_inputs,
            )

        checked_count = 0
        for key in (
            "open_redirect_validation",
            "ssrf_validation",
            "idor_validation",
            "token_reuse_validation",
        ):
            self.assertIn(key, summary["results"])
            if not summary["results"][key]:
                continue
            checked_count += 1
            item = summary["results"][key][0]
            self.assertEqual(item["schema_version"], "validation_result.v2")
            self.assertIn("validator", item)
            self.assertIn("category", item)
            self.assertIn("status", item)
            self.assertIn("url", item)
            self.assertIn("in_scope", item)
            self.assertIn("evidence", item)
            self.assertIn("http", item)
            self.assertIn("validation_actions", item)
        self.assertGreaterEqual(checked_count, 2)

    def test_scope_check_marks_out_of_scope_items_as_skipped(self) -> None:
        analysis_results: dict[str, list[dict[str, Any]]] = {
            "ssrf_candidate_finder": [],
            "idor_candidate_finder": [],
            "token_leak_detector": [],
            "behavior_analysis_layer": [],
        }
        ranked_priority_urls: list[dict[str, Any]] = [
            {"url": "https://evil.com/continue?next=https://attacker.net", "score": 4}
        ]
        runtime_inputs = {
            "urls": ["https://in-scope.example.com/"],
            "responses": [],
        }
        validation_settings = {"blackbox_validation": {"active_probe_enabled": False}}

        if True:
            summary = execute_validation_runtime(
                analysis_results,
                ranked_priority_urls,
                validation_settings,
                runtime_inputs=runtime_inputs,
            )

        item = summary["results"]["open_redirect_validation"][0]
        self.assertEqual(item["status"], "skipped")
        self.assertFalse(item["in_scope"])
        self.assertEqual(item["error"]["code"], "out_of_scope")

    def test_http_probe_failures_are_reported_clearly(self) -> None:
        analysis_results: dict[str, list[dict[str, Any]]] = {
            "ssrf_candidate_finder": [],
            "idor_candidate_finder": [],
            "token_leak_detector": [],
            "behavior_analysis_layer": [],
        }
        ranked_priority_urls: list[dict[str, Any]] = [
            {
                "url": "https://app.example.com/continue?next=https://external.example.net/callback",
                "score": 4,
            }
        ]
        runtime_inputs = {"urls": ["https://app.example.com/"], "responses": []}
        validation_settings = {
            "blackbox_validation": {"active_probe_enabled": True, "retry_attempts": 2}
        }

        with (
            patch("src.execution.validators.engine._http_client.fetch_response", return_value=None),

        ):
            summary = execute_validation_runtime(
                analysis_results,
                ranked_priority_urls,
                validation_settings,
                runtime_inputs=runtime_inputs,
            )

        item = summary["results"]["open_redirect_validation"][0]
        self.assertEqual(item["status"], "error")
        self.assertEqual(item["error"]["code"], "http_probe_failed")
        self.assertEqual(item["http"]["attempts"], 2)
        self.assertGreaterEqual(summary["metric"]["error_count"], 1)

    def test_validator_selection_is_configurable(self) -> None:
        analysis_results = {
            "ssrf_candidate_finder": [
                {
                    "url": "https://app.example.com/fetch?url=http://169.254.169.254",
                    "score": 8,
                    "signals": ["internal_host_reference:url"],
                    "parameters": ["url"],
                }
            ],
            "idor_candidate_finder": [],
            "token_leak_detector": [],
            "behavior_analysis_layer": [],
        }
        ranked_priority_urls: list[dict[str, Any]] = []
        runtime_inputs = {"urls": ["https://app.example.com/"], "responses": []}
        validation_settings = {
            "blackbox_validation": {
                "active_probe_enabled": False,
                "enabled_validators": ["ssrf"],
            }
        }

        if True:
            summary = execute_validation_runtime(
                analysis_results,
                ranked_priority_urls,
                validation_settings,
                runtime_inputs=runtime_inputs,
            )

        self.assertEqual(summary["settings"]["enabled_validators"], ["ssrf"])
        self.assertIn("ssrf_validation", summary["results"])
        self.assertNotIn("open_redirect_validation", summary["results"])
        self.assertNotIn("idor_validation", summary["results"])
        self.assertNotIn("token_reuse_validation", summary["results"])

    def test_unknown_validator_selection_does_not_fallback_to_defaults(self) -> None:
        analysis_results = {
            "ssrf_candidate_finder": [
                {
                    "url": "https://app.example.com/fetch?url=http://169.254.169.254",
                    "score": 8,
                    "signals": ["internal_host_reference:url"],
                    "parameters": ["url"],
                }
            ],
            "idor_candidate_finder": [
                {
                    "url": "https://app.example.com/api/users?id=100",
                    "score": 7,
                    "signals": ["numeric_query_identifier:id"],
                    "query_keys": ["id"],
                    "has_numeric_identifier": True,
                    "comparison": {},
                }
            ],
            "token_leak_detector": [],
            "behavior_analysis_layer": [],
        }
        runtime_inputs = {"urls": ["https://app.example.com/"], "responses": []}
        validation_settings = {
            "blackbox_validation": {
                "active_probe_enabled": False,
                "enabled_validators": ["nonexistent_validator"],
            }
        }

        if True:
            summary = execute_validation_runtime(
                analysis_results,
                [],
                validation_settings,
                runtime_inputs=runtime_inputs,
            )

        self.assertTrue(summary["settings"]["validator_selection_explicit"])
        self.assertEqual(summary["settings"]["requested_validators"], ["nonexistent_validator"])
        self.assertEqual(summary["settings"]["enabled_validators"], [])
        self.assertNotIn("ssrf_validation", summary["results"])
        self.assertNotIn("idor_validation", summary["results"])
        self.assertNotIn("csrf_validation", summary["results"])
        self.assertNotIn("xss_validation", summary["results"])
        self.assertGreaterEqual(len(summary["errors"]), 1)
        self.assertEqual(summary["errors"][0]["error"]["code"], "unknown_validator")


if __name__ == "__main__":
    unittest.main()
