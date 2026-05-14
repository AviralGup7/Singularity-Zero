"""Tests for decision prioritization module."""

import pytest

from src.analysis.intelligence.decision_engine import (
    _get_dynamic_thresholds,
    _is_likely_false_positive,
)
from src.decision.prioritization import (
    annotate_finding_decisions,
    classify_finding,
    filter_reportable_findings,
)


class TestClassifyFinding:
    def test_high_confidence_with_diff_returns_high(self) -> None:
        item = {
            "confidence": 0.85,
            "evidence": {
                "diff": {"status_changed": True, "content_changed": True},
            },
            "combined_signal": "auth_tamper + xss",
        }
        result = classify_finding(item)
        assert result["decision"] == "HIGH"

    def test_low_confidence_no_evidence_returns_drop(self) -> None:
        item = {
            "confidence": 0.10,
            "evidence": {"diff": {}},
            "combined_signal": "",
        }
        result = classify_finding(item)
        assert result["decision"] == "DROP"

    def test_reproducible_finding_returns_high(self) -> None:
        item = {
            "confidence": 0.70,
            "evidence": {
                "reproducible": True,
                "diff": {"status_changed": True},
            },
            "combined_signal": "ssrf",
        }
        result = classify_finding(item)
        assert result["decision"] == "HIGH"

    def test_trust_boundary_shift_returns_high(self) -> None:
        item = {
            "confidence": 0.50,
            "evidence": {
                "trust_boundary_shift": True,
                "diff": {},
            },
            "combined_signal": "",
        }
        result = classify_finding(item)
        assert result["decision"] == "HIGH"

    def test_cross_host_trust_boundary_returns_high(self) -> None:
        item = {
            "confidence": 0.40,
            "evidence": {
                "trust_boundary": "cross-host",
                "diff": {},
            },
            "combined_signal": "",
        }
        result = classify_finding(item)
        assert result["decision"] == "HIGH"

    def test_medium_confidence_returns_medium(self) -> None:
        item = {
            "confidence": 0.60,
            "evidence": {"diff": {}},
            "combined_signal": "anomaly",
        }
        result = classify_finding(item)
        assert result["decision"] == "MEDIUM"

    def test_intra_run_confirmed_returns_high(self) -> None:
        item = {
            "confidence": 0.65,
            "evidence": {
                "intra_run_confirmed": True,
                "diff": {"status_changed": True},
            },
            "combined_signal": "ssrf",
        }
        result = classify_finding(item)
        assert result["decision"] == "HIGH"

    def test_cross_run_reproducible_returns_high(self) -> None:
        item = {
            "confidence": 0.55,
            "evidence": {
                "cross_run_reproducible": True,
                "diff": {"status_changed": True},
            },
            "combined_signal": "xss",
        }
        result = classify_finding(item)
        assert result["decision"] == "HIGH"

    def test_fp_suppression_downgrades_medium(self) -> None:
        item = {
            "confidence": 0.60,
            "evidence": {
                "diff": {"mutated_status": 429},
                "body_snippet": "rate limit exceeded",
            },
            "combined_signal": "anomaly",
        }
        result = classify_finding(item)
        assert result["decision"] == "DROP"

    def test_fp_suppression_does_not_drop_reproducible(self) -> None:
        item = {
            "confidence": 0.70,
            "evidence": {
                "reproducible": True,
                "diff": {"mutated_status": 429},
                "body_snippet": "rate limit exceeded",
            },
            "combined_signal": "ssrf",
        }
        result = classify_finding(item)
        assert result["decision"] != "DROP"

    def test_return_has_decision_key(self) -> None:
        item = {"confidence": 0.5, "evidence": {"diff": {}}, "combined_signal": ""}
        result = classify_finding(item)
        assert "decision" in result

    def test_return_has_reason_key(self) -> None:
        item = {"confidence": 0.5, "evidence": {"diff": {}}, "combined_signal": ""}
        result = classify_finding(item)
        assert "reason" in result

    def test_return_has_confidence_factors(self) -> None:
        item = {"confidence": 0.5, "evidence": {"diff": {}}, "combined_signal": ""}
        result = classify_finding(item)
        assert "confidence_factors" in result

    def test_return_has_diff_score(self) -> None:
        item = {"confidence": 0.5, "evidence": {"diff": {}}, "combined_signal": ""}
        result = classify_finding(item)
        assert "diff_score" in result

    def test_return_has_thresholds_used(self) -> None:
        item = {"confidence": 0.5, "evidence": {"diff": {}}, "combined_signal": ""}
        result = classify_finding(item)
        assert "thresholds_used" in result


class TestAnnotateFindingDecisions:
    def test_annotates_each_finding(self) -> None:
        findings = [
            {"confidence": 0.8, "evidence": {"diff": {}}, "combined_signal": "xss"},
            {"confidence": 0.2, "evidence": {"diff": {}}, "combined_signal": ""},
        ]
        result = annotate_finding_decisions(findings)
        assert len(result) == 2

    def test_adds_decision_key(self) -> None:
        findings = [{"confidence": 0.5, "evidence": {"diff": {}}, "combined_signal": ""}]
        result = annotate_finding_decisions(findings)
        assert "decision" in result[0]

    def test_adds_reportable_key(self) -> None:
        findings = [{"confidence": 0.5, "evidence": {"diff": {}}, "combined_signal": ""}]
        result = annotate_finding_decisions(findings)
        assert "reportable" in result[0]

    def test_reportable_false_for_drop(self) -> None:
        findings = [{"confidence": 0.1, "evidence": {"diff": {}}, "combined_signal": ""}]
        result = annotate_finding_decisions(findings)
        if result[0]["decision"] == "DROP":
            assert result[0]["reportable"] is False

    def test_preserves_original_fields(self) -> None:
        findings = [
            {
                "confidence": 0.5,
                "evidence": {"diff": {}},
                "combined_signal": "",
                "url": "https://example.com",
            }
        ]
        result = annotate_finding_decisions(findings)
        assert result[0].get("url") == "https://example.com"

    def test_adds_diff_score(self) -> None:
        findings = [{"confidence": 0.5, "evidence": {"diff": {}}, "combined_signal": ""}]
        result = annotate_finding_decisions(findings)
        assert "diff_score" in result[0]

    def test_adds_diff_classification(self) -> None:
        findings = [{"confidence": 0.5, "evidence": {"diff": {}}, "combined_signal": ""}]
        result = annotate_finding_decisions(findings)
        assert "diff_classification" in result[0]

    def test_adds_suppress_reason(self) -> None:
        findings = [{"confidence": 0.5, "evidence": {"diff": {}}, "combined_signal": ""}]
        result = annotate_finding_decisions(findings)
        assert "suppress_reason" in result[0]


class TestFilterReportableFindings:
    def test_filters_out_drop_decisions(self) -> None:
        findings = [
            {"decision": "HIGH", "url": "a"},
            {"decision": "DROP", "url": "b"},
            {"decision": "MEDIUM", "url": "c"},
        ]
        result = filter_reportable_findings(findings)
        assert len(result) == 2

    def test_keeps_high_decisions(self) -> None:
        findings = [{"decision": "HIGH"}]
        result = filter_reportable_findings(findings)
        assert len(result) == 1

    def test_keeps_medium_decisions(self) -> None:
        findings = [{"decision": "MEDIUM"}]
        result = filter_reportable_findings(findings)
        assert len(result) == 1

    def test_keeps_low_decisions(self) -> None:
        findings = [{"decision": "LOW"}]
        result = filter_reportable_findings(findings)
        assert len(result) == 1

    def test_empty_list_returns_empty(self) -> None:
        result = filter_reportable_findings([])
        assert result == []

    def test_all_drops_returns_empty(self) -> None:
        findings = [{"decision": "DROP"}, {"decision": "DROP"}]
        result = filter_reportable_findings(findings)
        assert result == []


class TestDynamicThresholds:
    def test_default_thresholds(self) -> None:
        result = _get_dynamic_thresholds()
        assert result["low"] == pytest.approx(0.45)
        assert result["medium"] == pytest.approx(0.58)
        assert result["high"] == pytest.approx(0.72)

    def test_api_heavy_lowers_thresholds(self) -> None:
        result = _get_dynamic_thresholds({"api_heavy": True})
        assert result["low"] < 0.45
        assert result["medium"] < 0.58

    def test_high_auth_complexity_raises_thresholds(self) -> None:
        result = _get_dynamic_thresholds({"auth_complexity": 0.9})
        assert result["low"] > 0.45

    def test_low_historical_precision_raises_thresholds(self) -> None:
        result = _get_dynamic_thresholds({"historical_precision": 0.2})
        assert result["low"] > 0.45

    def test_high_historical_precision_lowers_thresholds(self) -> None:
        result = _get_dynamic_thresholds({"historical_precision": 0.9})
        assert result["low"] < 0.45

    def test_focused_mode_lowers_thresholds(self) -> None:
        result = _get_dynamic_thresholds({"mode": "idor"})
        assert result["low"] < 0.45

    def test_thresholds_are_clamped(self) -> None:
        result = _get_dynamic_thresholds({"historical_precision": 0.1, "auth_complexity": 0.9})
        assert 0.25 <= result["low"] <= 0.70
        assert result["medium"] > result["low"]
        assert result["high"] > result["medium"]


class TestFPSuppression:
    def test_rate_limit_detected(self) -> None:
        is_fp, category = _is_likely_false_positive(429, "rate limit exceeded")
        assert is_fp is True
        assert category == "rate_limit"

    def test_waf_block_detected(self) -> None:
        is_fp, category = _is_likely_false_positive(403, "blocked by cloudflare waf")
        assert is_fp is True
        assert category == "waf_block"

    def test_no_fp_for_normal_response(self) -> None:
        is_fp, category = _is_likely_false_positive(200, '{"status": "ok"}')
        assert is_fp is False
        assert category == ""

    def test_cdn_error_detected(self) -> None:
        is_fp, category = _is_likely_false_positive(502, "bad gateway")
        assert is_fp is True
        assert category == "cdn_error"
