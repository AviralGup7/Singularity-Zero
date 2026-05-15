"""Tests for detection coverage metrics.

Verifies that detection coverage calculations are accurate,
all categories are represented, and HTML output is well-formed.
"""

from typing import Any

from src.reporting.detection_coverage import (
    ALL_DETECTION_CATEGORIES,
    detection_coverage_section,
)


class TestAllDetectionCategories:
    """Test the ALL_DETECTION_CATEGORIES dictionary."""

    def test_not_empty(self) -> None:
        assert len(ALL_DETECTION_CATEGORIES) > 0

    def test_has_idor(self) -> None:
        assert "idor" in ALL_DETECTION_CATEGORIES

    def test_has_ssrf(self) -> None:
        assert "ssrf" in ALL_DETECTION_CATEGORIES

    def test_has_xss(self) -> None:
        assert "xss" in ALL_DETECTION_CATEGORIES

    def test_has_token_leak(self) -> None:
        assert "token_leak" in ALL_DETECTION_CATEGORIES

    def test_has_cors(self) -> None:
        assert "cors" in ALL_DETECTION_CATEGORIES

    def test_has_csrf(self) -> None:
        assert "csrf" in ALL_DETECTION_CATEGORIES

    def test_has_ssti(self) -> None:
        assert "ssti" in ALL_DETECTION_CATEGORIES

    def test_has_open_redirect(self) -> None:
        assert "open_redirect" in ALL_DETECTION_CATEGORIES

    def test_has_access_control(self) -> None:
        assert "access_control" in ALL_DETECTION_CATEGORIES

    def test_has_authentication_bypass(self) -> None:
        assert "authentication_bypass" in ALL_DETECTION_CATEGORIES

    def test_has_server_side_injection(self) -> None:
        assert "server_side_injection" in ALL_DETECTION_CATEGORIES

    def test_has_ai_surface(self) -> None:
        assert "ai_surface" in ALL_DETECTION_CATEGORIES

    def test_has_race_condition(self) -> None:
        assert "race_condition" in ALL_DETECTION_CATEGORIES

    def test_has_session(self) -> None:
        assert "session" in ALL_DETECTION_CATEGORIES

    def test_has_payment(self) -> None:
        assert "payment" in ALL_DETECTION_CATEGORIES

    def test_all_entries_have_name(self) -> None:
        for cat, info in ALL_DETECTION_CATEGORIES.items():
            assert "name" in info, f"Category {cat} missing 'name'"
            assert info["name"], f"Category {cat} has empty name"

    def test_all_entries_have_severity_potential(self) -> None:
        for cat, info in ALL_DETECTION_CATEGORIES.items():
            assert "severity_potential" in info, f"Category {cat} missing 'severity_potential'"

    def test_all_entries_have_test_type(self) -> None:
        for cat, info in ALL_DETECTION_CATEGORIES.items():
            assert "test_type" in info, f"Category {cat} missing 'test_type'"

    def test_severity_values_are_valid(self) -> None:
        valid_severities = {"Low", "Medium", "High", "Critical"}
        for cat, info in ALL_DETECTION_CATEGORIES.items():
            assert info["severity_potential"] in valid_severities, (
                f"Category {cat} has invalid severity: {info['severity_potential']}"
            )

    def test_category_count(self) -> None:
        assert len(ALL_DETECTION_CATEGORIES) >= 20


class TestDetectionCoverageSection:
    """Test detection_coverage_section HTML generation."""

    def test_returns_valid_html(self) -> None:
        result = detection_coverage_section([], {})
        assert "<section" in result
        assert "Detection Coverage" in result
        assert "</section>" in result

    def test_shows_zero_coverage(self) -> None:
        result = detection_coverage_section([], {})
        assert "0%" in result
        assert "0</strong>" in result

    def test_contains_table_structure(self) -> None:
        result = detection_coverage_section([], {})
        assert "<table" in result
        assert "<thead>" in result
        assert "<tbody>" in result
        assert "</table>" in result

    def test_table_has_expected_columns(self) -> None:
        result = detection_coverage_section([], {})
        assert "Category" in result
        assert "ID" in result
        assert "Severity Potential" in result
        assert "Test Type" in result
        assert "Status" in result

    def test_shows_not_tested_status(self) -> None:
        result = detection_coverage_section([], {})
        assert "Not tested" in result

    def test_with_findings(self) -> None:
        findings: list[dict[str, Any]] = [
            {"category": "xss", "url": "https://example.com/search", "severity": "high"},
            {"category": "xss", "url": "https://example.com/profile", "severity": "medium"},
            {"category": "idor", "url": "https://example.com/api/users/1", "severity": "high"},
        ]
        analysis_results: dict[str, list[dict[str, Any]]] = {
            "reflected_xss_probe": [{"url": "https://example.com/search"}],
            "idor_candidate_finder": [{"url": "https://example.com/api/users/1"}],
        }
        result = detection_coverage_section(findings, analysis_results)
        assert "2 finding(s)" in result
        assert "1 finding(s)" in result

    def test_with_validation_summary(self) -> None:
        findings: list[dict[str, Any]] = [
            {"category": "xss", "url": "https://example.com", "severity": "high"},
        ]
        analysis_results: dict[str, list[dict[str, Any]]] = {
            "reflected_xss_probe": [{"url": "https://example.com"}],
        }
        validation_summary: dict[str, Any] = {
            "results": {"xss": [{"validated": True}]},
        }
        result = detection_coverage_section(findings, analysis_results, validation_summary)
        assert "xss" in result.lower()

    def test_coverage_percentage_calculation(self) -> None:
        findings: list[dict[str, Any]] = []
        analysis_results: dict[str, list[dict[str, Any]]] = {
            "reflected_xss_probe": [],
            "idor_candidate_finder": [],
            "token_leak_detector": [],
        }
        result = detection_coverage_section(findings, analysis_results)
        total = len(ALL_DETECTION_CATEGORIES)
        assert f"<strong>3</strong> / {total}" in result

    def test_all_categories_in_table(self) -> None:
        result = detection_coverage_section([], {})
        for cat, info in ALL_DETECTION_CATEGORIES.items():
            assert info["name"] in result, f"Category {info['name']} not found in output"

    def test_coverage_gaps_listed(self) -> None:
        result = detection_coverage_section([], {})
        assert "Coverage Gaps" in result
        assert "not tested" in result.lower()

    def test_tested_category_shows_clean_status(self) -> None:
        findings: list[dict[str, Any]] = []
        analysis_results: dict[str, list[dict[str, Any]]] = {
            "reflected_xss_probe": [],
        }
        result = detection_coverage_section(findings, analysis_results)
        assert "Tested - No issues" in result

    def test_multiple_findings_same_category(self) -> None:
        findings: list[dict[str, Any]] = [
            {"category": "xss", "url": f"https://example.com/{i}", "severity": "high"}
            for i in range(5)
        ]
        analysis_results: dict[str, list[dict[str, Any]]] = {
            "reflected_xss_probe": [],
        }
        result = detection_coverage_section(findings, analysis_results)
        assert "5 finding(s)" in result

    def test_unknown_category_ignored(self) -> None:
        findings: list[dict[str, Any]] = [
            {"category": "unknown_vuln", "url": "https://example.com", "severity": "low"},
        ]
        analysis_results: dict[str, list[dict[str, Any]]] = {}
        result = detection_coverage_section(findings, analysis_results)
        assert "unknown_vuln" not in result

    def test_html_escaping_in_output(self) -> None:
        findings: list[dict[str, Any]] = [
            {
                "category": "xss",
                "url": "https://example.com/<script>alert(1)</script>",
                "severity": "high",
            },
        ]
        analysis_results: dict[str, list[dict[str, Any]]] = {
            "reflected_xss_probe": [],
        }
        result = detection_coverage_section(findings, analysis_results)
        assert "<script>" not in result
        assert "alert(1)" not in result
        assert "1 finding(s)" in result
