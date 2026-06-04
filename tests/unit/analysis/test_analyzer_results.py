"""Unit tests for src.analysis.analyzer_results."""

import unittest

import pytest

from src.analysis.analyzer_results import build_analyzer_result


@pytest.mark.unit
class TestBuildAnalyzerResultBasic(unittest.TestCase):
    def test_returns_dict(self) -> None:
        result = build_analyzer_result("https://example.com/api")
        self.assertIsInstance(result, dict)

    def test_includes_url(self) -> None:
        result = build_analyzer_result("https://example.com/api")
        self.assertEqual(result["url"], "https://example.com/api")

    def test_includes_endpoint_keys_by_default(self) -> None:
        result = build_analyzer_result("https://example.com/api")
        for key in ("endpoint_key", "endpoint_base_key", "endpoint_type"):
            self.assertIn(key, result)

    def test_status_code_from_kwarg(self) -> None:
        result = build_analyzer_result("https://example.com/", status_code=200)
        self.assertEqual(result["status_code"], 200)

    def test_status_code_from_response_dict(self) -> None:
        result = build_analyzer_result(
            "https://example.com/", response={"status_code": 404}
        )
        self.assertEqual(result["status_code"], 404)

    def test_explicit_status_code_wins(self) -> None:
        result = build_analyzer_result(
            "https://example.com/", status_code=500, response={"status_code": 200}
        )
        self.assertEqual(result["status_code"], 500)

    def test_extra_fields_merged(self) -> None:
        result = build_analyzer_result(
            "https://example.com/", custom="value", count=3
        )
        self.assertEqual(result["custom"], "value")
        self.assertEqual(result["count"], 3)


@pytest.mark.unit
class TestBuildAnalyzerResultFlags(unittest.TestCase):
    def test_exclude_endpoint_keys(self) -> None:
        result = build_analyzer_result(
            "https://example.com/api", include_endpoint_keys=False
        )
        self.assertNotIn("endpoint_key", result)
        self.assertNotIn("endpoint_base_key", result)
        self.assertIn("endpoint_type", result)

    def test_include_endpoint_keys_explicit_true(self) -> None:
        result = build_analyzer_result(
            "https://example.com/api", include_endpoint_keys=True
        )
        self.assertIn("endpoint_key", result)
        self.assertIn("endpoint_base_key", result)
        self.assertIn("endpoint_type", result)


@pytest.mark.unit
class TestBuildAnalyzerResultEdgeCases(unittest.TestCase):
    def test_empty_url(self) -> None:
        result = build_analyzer_result("")
        self.assertEqual(result["url"], "")
        self.assertNotIn("endpoint_key", result)
        self.assertNotIn("endpoint_type", result)

    def test_none_url_becomes_empty_string(self) -> None:
        result = build_analyzer_result(None)
        self.assertEqual(result["url"], "")

    def test_response_with_non_int_status_still_stored(self) -> None:
        result = build_analyzer_result("https://x.com/", response={"status_code": "200"})
        self.assertEqual(result["status_code"], "200")

    def test_response_with_missing_status_no_code(self) -> None:
        result = build_analyzer_result("https://x.com/", response={"body": "ok"})
        self.assertNotIn("status_code", result)

    def test_extra_can_override_endpoint_type(self) -> None:
        result = build_analyzer_result(
            "https://example.com/api", endpoint_type="custom"
        )
        self.assertEqual(result["endpoint_type"], "custom")


if __name__ == "__main__":
    unittest.main()
