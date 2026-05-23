"""Unit tests for the SHAPExplainability Engine (SHAPExplainer)."""

from __future__ import annotations

from src.intelligence.ml.shap_explainer import SHAPExplainer


def test_shap_explainer_computes_contributions_and_marginal_impacts() -> None:
    """Verify that SHAPExplainer accurately decomposes finding severity scores."""
    explainer = SHAPExplainer()

    finding = {
        "id": "test-finding-1",
        "title": "SQL Injection in Parameter",
        "category": "injection",
        "severity": "critical",
        "confidence": 0.95,
        "cvss_score": 9.8,
        "score": 95.0,
        "url": "http://example.com/api/v1/search?query=test",
        "endpoint_type": "api",
        "parameter_type": "query",
        "decision": "candidate",
        "response_delta_score": 8.5,
        "diff_score": 7.0,
        "evidence": {
            "reproducible": True,
            "confirmed": True,
            "diff": {
                "status_changed": True,
                "content_changed": True,
                "redirect_changed": False
            },
            "signals": ["syntax_error"]
        }
    }

    explanation = explainer.explain(finding)

    # Basic structure checks
    assert explanation["finding_id"] == "test-finding-1"
    assert "severity_score" in explanation
    assert "severity_percentage" in explanation
    assert "base_value_logit" in explanation
    assert "base_value_prob" in explanation
    assert "final_logit" in explanation
    assert explanation["is_fallback_model"] is True
    assert "diagnostic_summary" in explanation

    # Verify contributions list
    contributions = explanation["contributions"]
    assert len(contributions) > 0

    # Ensure each contribution has the required keys
    for contrib in contributions:
        assert "feature" in contrib
        assert "label" in contrib
        assert "value" in contrib
        assert "logit_contribution" in contrib
        assert "probability_impact" in contrib
        assert "description" in contrib

    # Ensure logit contributions sum up to the final logit
    total_calculated_logit = explanation["base_value_logit"]
    for contrib in contributions:
        total_calculated_logit += contrib["logit_contribution"]

    assert abs(total_calculated_logit - explanation["final_logit"]) < 1e-4

    # Ensure diagnostic summary contains some text
    assert len(explanation["diagnostic_summary"]) > 0
    assert "reproducible" in explanation["diagnostic_summary"].lower() or "severity is highly driven by" in explanation["diagnostic_summary"].lower()
