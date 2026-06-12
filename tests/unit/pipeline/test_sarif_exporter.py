"""Tests for the SARIF 2.1 exporter."""

from __future__ import annotations

import json
from typing import Any

import pytest

from src.reporting.sarif_exporter import (
    export_findings_to_sarif,
    merge_sarif_documents,
)


def _finding(**overrides: Any) -> dict[str, Any]:
    base = {
        "category": "xss",
        "title": "Reflected XSS in /search",
        "severity": "high",
        "url": "https://api.example.com/search?q=x",
        "confidence": 0.9,
        "score": 80,
        "cwe_id": "CWE-79",
        "description": "User input is reflected unescaped in the response body.",
    }
    base.update(overrides)
    return base


class TestSarifExport:
    def test_basic_export(self) -> None:
        result = export_findings_to_sarif([_finding()])
        assert result.dropped == 0
        assert result.total == 1
        doc = result.document
        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-2.1.0.json")
        runs = doc["runs"]
        assert len(runs) == 1
        run = runs[0]
        assert run["tool"]["driver"]["name"] == "cyber-security-test-pipeline"
        assert len(run["results"]) == 1
        assert len(run["tool"]["driver"]["rules"]) == 1

    def test_severity_to_level(self) -> None:
        cases = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        for severity, expected in cases.items():
            result = export_findings_to_sarif([_finding(severity=severity)])
            assert result.document["runs"][0]["results"][0]["level"] == expected

    def test_artifact_location_for_https_url(self) -> None:
        result = export_findings_to_sarif([_finding(url="https://api.example.com/v1/users")])
        loc = result.document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "https://api.example.com/v1/users"
        assert loc["artifactLocation"]["uriBaseId"] == "api.example.com/v1"

    def test_fingerprint_is_deterministic(self) -> None:
        a = export_findings_to_sarif([_finding()]).document["runs"][0]["results"][0][
            "partialFingerprints"
        ]["primary"]
        b = export_findings_to_sarif([_finding()]).document["runs"][0]["results"][0][
            "partialFingerprints"
        ]["primary"]
        assert a == b
        # Different url => different fingerprint
        c = export_findings_to_sarif([_finding(url="https://x.example/other")]).document["runs"][0][
            "results"
        ][0]["partialFingerprints"]["primary"]
        assert a != c

    def test_false_positive_excluded_by_default(self) -> None:
        result = export_findings_to_sarif(
            [_finding(severity="critical", lifecycle_state="FALSE_POSITIVE")]
        )
        assert result.total == 0
        assert result.document["runs"][0]["results"] == []

    def test_false_positive_included_when_requested(self) -> None:
        result = export_findings_to_sarif(
            [_finding(severity="critical", lifecycle_state="FALSE_POSITIVE")],
            include_false_positives=True,
        )
        assert result.total == 1
        assert len(result.document["runs"][0]["results"]) == 1

    def test_fp_decision_field_excluded(self) -> None:
        result = export_findings_to_sarif(
            [_finding(ai_triage_decision="FP", ai_confidence_score=0.95)]
        )
        assert result.total == 0

    def test_rule_id_dedup(self) -> None:
        result = export_findings_to_sarif(
            [
                _finding(url="https://a.example/x"),
                _finding(url="https://a.example/y"),
            ]
        )
        rules = result.document["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1  # same category+severity dedups

    def test_malformed_finding_does_not_crash(self) -> None:
        class _BadFinding:
            def get(self, key: str, default: object = None) -> object:
                if key == "url":
                    raise RuntimeError("simulated url access failure")
                return default

            def __getitem__(self, key: str) -> object:
                if key == "url":
                    raise RuntimeError("simulated url access failure")
                raise KeyError(key)

        result = export_findings_to_sarif(
            [
                _finding(),
                _BadFinding(),
                _finding(severity="critical"),
            ]
        )
        assert result.dropped == 1
        assert result.total == 3
        # Two findings were successfully exported, one was dropped.
        assert len(result.document["runs"][0]["results"]) == 2
        assert "logs" in result.document["runs"][0]

    def test_empty_findings(self) -> None:
        result = export_findings_to_sarif([])
        assert result.dropped == 0
        assert result.total == 0
        assert result.document["runs"][0]["results"] == []
        # Empty runs shouldn't add empty originalUriBaseIds
        assert "originalUriBaseIds" not in result.document["runs"][0]

    def test_properties_include_severity_and_cwe(self) -> None:
        result = export_findings_to_sarif([_finding()])
        props = result.document["runs"][0]["results"][0]["properties"]
        assert props["severity"] == "high"
        assert props["cwe"] == "CWE-79"
        assert (
            "security-severity"
            in result.document["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
        )

    def test_custom_tool_metadata(self) -> None:
        result = export_findings_to_sarif(
            [_finding()], tool_name="custom", tool_version="1.2.3", info_uri="https://x"
        )
        driver = result.document["runs"][0]["tool"]["driver"]
        assert driver["name"] == "custom"
        assert driver["version"] == "1.2.3"
        assert driver["informationUri"] == "https://x"


class TestMergeSarifDocuments:
    def test_merge_combines_rules_and_results(self) -> None:
        a = export_findings_to_sarif([_finding(category="xss")]).document
        b = export_findings_to_sarif([_finding(category="sqli", url="https://x/sqli")]).document
        merged = merge_sarif_documents([a, b])
        runs = merged["runs"]
        assert len(runs) == 1
        assert len(runs[0]["results"]) == 2
        assert len(runs[0]["tool"]["driver"]["rules"]) == 2

    def test_merge_dedups_rules(self) -> None:
        a = export_findings_to_sarif([_finding(category="xss", url="https://a")]).document
        b = export_findings_to_sarif([_finding(category="xss", url="https://b")]).document
        merged = merge_sarif_documents([a, b])
        assert len(merged["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(merged["runs"][0]["results"]) == 2

    def test_merge_empty_documents(self) -> None:
        merged = merge_sarif_documents([])
        assert merged["runs"][0]["results"] == []


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low"])
def test_sarif_is_valid_json(severity: str) -> None:
    result = export_findings_to_sarif([_finding(severity=severity)])
    raw = json.dumps(result.document)
    # Round-trip through json to validate the structure is serializable.
    json.loads(raw)
