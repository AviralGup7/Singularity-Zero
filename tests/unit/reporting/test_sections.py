"""Tests for reporting section rendering functions.

Covers findings sections, general sections, and validation sections
to ensure HTML output is well-formed and contains expected content.
"""

from typing import Any

from src.reporting.sections_findings import (
    high_confidence_shortlist_section,
    manual_verification_section,
    signal_quality_section,
    top_findings_section,
    verified_exploits_section,
)
from src.reporting.sections_general import (
    analysis_section,
    count_cards,
    detection_gap_section,
    diff_cards,
    high_value_section,
    list_section,
    module_metrics_section,
    next_steps_section,
    prioritized_endpoints_section,
    screenshot_section,
    technology_section,
    validation_plan_section,
    vrt_coverage_section,
)


class TestFindingsSections:
    """Test findings-related section renderers."""

    def test_top_findings_empty(self) -> None:
        result = top_findings_section({"top_actionable_findings": []})
        assert "<section>" in result
        assert "No prioritized findings" in result

    def test_top_findings_with_data(self) -> None:
        summary: dict[str, Any] = {
            "top_actionable_findings": [
                {
                    "severity": "high",
                    "title": "SQL Injection found",
                    "url": "https://example.com/api?id=1",
                    "score": 85,
                    "confidence": 0.9,
                    "history_status": "new",
                    "explanation": "Status changed on mutation",
                    "endpoint_type": "API",
                    "evidence": {"endpoint_key": "api_id_1"},
                },
            ],
        }
        result = top_findings_section(summary)
        assert "<section>" in result
        assert "SQL Injection found" in result
        assert "HIGH" in result
        assert "example.com" in result

    def test_top_findings_limits_to_five(self) -> None:
        findings = [
            {
                "severity": "info",
                "title": f"Finding {i}",
                "url": f"https://example.com/{i}",
                "score": i,
                "confidence": 0.5,
                "history_status": "new",
                "explanation": "",
                "evidence": {"endpoint_key": f"ep_{i}"},
            }
            for i in range(10)
        ]
        result = top_findings_section({"top_actionable_findings": findings})
        count = result.count("<li>")
        assert count <= 5

    def test_high_confidence_shortlist_empty(self) -> None:
        result = high_confidence_shortlist_section({"high_confidence_shortlist": []})
        assert "No shortlist entries" in result

    def test_high_confidence_shortlist_with_data(self) -> None:
        summary: dict[str, Any] = {
            "high_confidence_shortlist": [
                {
                    "severity": "medium",
                    "title": "Potential XSS",
                    "url": "https://example.com/search?q=test",
                    "confidence": 0.85,
                    "history_status": "new",
                    "category": "xss",
                    "next_step": "Verify with active probe",
                },
            ],
        }
        result = high_confidence_shortlist_section(summary)
        assert "Potential XSS" in result
        assert "85%" in result

    def test_manual_verification_queue_empty(self) -> None:
        result = manual_verification_section({"manual_verification_queue": []})
        assert "No queued review tasks" in result

    def test_verified_exploits_empty(self) -> None:
        result = verified_exploits_section({"verified_exploits": []})
        assert "No evidence-backed leads" in result

    def test_verified_exploits_with_data(self) -> None:
        summary: dict[str, Any] = {
            "verified_exploits": [
                {
                    "severity": "critical",
                    "title": "Confirmed RCE",
                    "url": "https://example.com/exec?cmd=test",
                },
            ],
        }
        result = verified_exploits_section(summary)
        assert "Confirmed RCE" in result
        assert "Validated Leads" in result

    def test_signal_quality_section(self) -> None:
        summary: dict[str, Any] = {
            "top_actionable_findings": [
                {"confidence": 0.9, "endpoint_type": "API"},
                {"confidence": 0.3, "endpoint_type": "AUTH"},
                {"confidence": 0.85, "endpoint_type": "API", "combined_signal": "xss"},
            ],
        }
        result = signal_quality_section(summary)
        assert "Signal Quality" in result
        assert "Likely True Positives" in result
        assert "Likely Noise" in result


class TestGeneralSections:
    """Test general section renderers."""

    def test_count_cards(self) -> None:
        summary: dict[str, Any] = {"counts": {"urls": 42, "parameters": 15}}
        result = count_cards(summary)
        assert "urls" in result
        assert "42" in result
        assert "parameters" in result
        assert "15" in result

    def test_diff_cards_none(self) -> None:
        result = diff_cards(None)
        assert "No previous run" in result

    def test_diff_cards_with_data(self) -> None:
        diff: dict[str, Any] = {
            "artifacts": {
                "urls": {
                    "previous_count": 10,
                    "current_count": 12,
                    "added_count": 2,
                    "removed_count": 0,
                },
            },
        }
        result = diff_cards(diff)
        assert "+2" in result
        assert "-0" in result

    def test_list_section_empty(self) -> None:
        result = list_section("Test List", [])
        assert "No data" in result

    def test_list_section_with_items(self) -> None:
        result = list_section("Endpoints", ["https://a.com", "https://b.com"])
        assert "Endpoints" in result
        assert "a.com" in result
        assert "b.com" in result

    def test_list_section_respects_limit(self) -> None:
        items = [f"https://example.com/{i}" for i in range(50)]
        result = list_section("Many Items", items, limit=5)
        count = result.count("<li>")
        assert count <= 5

    def test_screenshot_section_empty(self) -> None:
        result = screenshot_section([])
        assert "No screenshots" in result

    def test_screenshot_section_with_data(self) -> None:
        screenshots: list[dict[str, Any]] = [
            {"url": "https://example.com", "file": "shots/001.png"},
        ]
        result = screenshot_section(screenshots)
        assert "Screenshots" in result
        assert "example.com" in result
        assert "001.png" in result

    def test_analysis_section_empty(self) -> None:
        result = analysis_section("Test", [])
        assert "No findings" in result

    def test_analysis_section_with_items(self) -> None:
        items: list[dict[str, Any]] = [{"url": "https://example.com", "finding": "test"}]
        result = analysis_section("Scanner", items)
        assert "Scanner" in result
        assert "example.com" in result

    def test_high_value_section_empty(self) -> None:
        result = high_value_section([])
        assert "No scored endpoints" in result

    def test_high_value_section_with_data(self) -> None:
        items: list[dict[str, Any]] = [
            {"url": "https://example.com/api", "score": 95, "has_parameters": True},
        ]
        result = high_value_section(items)
        assert "95" in result
        assert "with params" in result

    def test_prioritized_endpoints_empty(self) -> None:
        result = prioritized_endpoints_section({"prioritized_endpoints": []})
        assert "No enriched endpoint" in result

    def test_module_metrics_empty(self) -> None:
        result = module_metrics_section({"module_metrics": {}})
        assert "No module metrics" in result

    def test_module_metrics_with_data(self) -> None:
        summary: dict[str, Any] = {
            "module_metrics": {
                "nuclei_scan": {"status": "completed", "duration_seconds": 12.5},
                "http_scan": {"status": "completed", "duration_seconds": 8.3},
            },
        }
        result = module_metrics_section(summary)
        assert "Module Status" in result
        assert "nuclei scan" in result
        assert "completed" in result

    def test_next_steps_empty(self) -> None:
        result = next_steps_section({"next_steps": []})
        assert "No suggestions" in result

    def test_next_steps_with_data(self) -> None:
        summary: dict[str, Any] = {
            "next_steps": ["Run active XSS probe", "Validate IDOR candidate"],
        }
        result = next_steps_section(summary)
        assert "Next Step Suggestions" in result
        assert "XSS" in result

    def test_technology_section_empty(self) -> None:
        result = technology_section({"technology_summary": []})
        assert "No strong technology" in result

    def test_technology_section_with_data(self) -> None:
        summary: dict[str, Any] = {
            "technology_summary": [
                {"technology": "nginx", "count": 3},
                {"technology": "react", "count": 1},
            ],
        }
        result = technology_section(summary)
        assert "nginx" in result
        assert "3 hits" in result

    def test_vrt_coverage_section_empty(self) -> None:
        result = vrt_coverage_section({"vrt_coverage": {"entries": []}})
        assert "No coverage matrix" in result

    def test_vrt_coverage_section_with_data(self) -> None:
        summary: dict[str, Any] = {
            "vrt_coverage": {
                "entries": [
                    {
                        "status": "direct",
                        "vrt_category": "Server-Side Injection",
                        "vulnerability_name": "SQL Injection",
                        "variant": "",
                        "active_checks": ["server_side_injection_surface_analyzer"],
                        "notes": "Test note",
                    },
                ],
                "summary": {"direct": 1, "signal_only": 0, "disabled": 0, "unsupported": 0},
            },
        }
        result = vrt_coverage_section(summary)
        assert "SQL Injection" in result
        assert "direct" in result

    def test_validation_plan_section_empty(self) -> None:
        result = validation_plan_section({"validation_plans": []})
        assert "No validation plans" in result

    def test_detection_gap_section_empty(self) -> None:
        result = detection_gap_section({"detection_coverage": {}})
        assert result == ""

    def test_detection_gap_section_with_data(self) -> None:
        summary: dict[str, Any] = {
            "detection_coverage": {
                "coverage_score": 0.5,
                "active_count": 10,
                "total_modules": 20,
                "coverage_by_category": {"xss": 2, "idor": 1},
                "signal_distribution": {"response_diff_engine": 5},
                "empty_modules": ["some_module"],
            },
        }
        result = detection_gap_section(summary)
        assert "Detection Coverage" in result
        assert "Detection Yield" in result
        assert "modules produced findings" in result
        assert "50%" in result
