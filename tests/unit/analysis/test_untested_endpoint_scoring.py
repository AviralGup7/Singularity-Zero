"""Coverage for endpoint intelligence scoring helpers."""

from __future__ import annotations

import pytest

from src.analysis.intelligence.endpoint_scoring import (
    _apply_cross_endpoint_correlation,
    _build_endpoint_reasoning,
    _parameter_sensitivity_score,
    _response_diff_weight,
)


@pytest.mark.unit
def test_response_diff_weight_status_and_similarity() -> None:
    assert _response_diff_weight({}) == 0
    error_to_ok = _response_diff_weight(
        {
            "status_changed": True,
            "original_status": 403,
            "mutated_status": 200,
            "body_similarity": 0.2,
            "changed": True,
        }
    )
    assert error_to_ok >= 5 + 4 + 8 + 2
    forbidden = _response_diff_weight(
        {
            "status_changed": True,
            "original_status": 200,
            "mutated_status": 403,
            "redirect_changed": True,
            "classification": "include",
        }
    )
    assert forbidden >= 5 + 3 + 4 + 2


@pytest.mark.unit
def test_parameter_sensitivity_accumulates_and_caps() -> None:
    score = _parameter_sensitivity_score(
        [
            {"parameter": "user_id"},
            {"parameter": "token"},
            {"parameter": "redirect"},
            {"parameter": "file"},
            {"parameter": "amount"},
            {"parameter": "role"},
            {"parameter": "query"},
        ]
    )
    assert score == 12
    assert _parameter_sensitivity_score([{"parameter": "user_id"}]) == 2
    assert _parameter_sensitivity_score([]) == 0


@pytest.mark.unit
def test_endpoint_reasoning_and_cross_correlation() -> None:
    record = {
        "signals": ["confirmed", "idor"],
        "trust_boundary": "cross-host",
        "evidence_modules": ["a", "b", "c", "d", "e"],
        "flow_labels": ["checkout"],
        "parameter_sensitivity": 5,
        "resource_group": "payments",
        "schema_markers": ["sensitive_card"],
    }
    text = _build_endpoint_reasoning(record, {"idor", "auth", "ssrf"}, 3, 0.8)
    assert "confirmed" in text.lower() or "Confirmed" in text
    assert "payments" in text
    assert "0.80" in text

    endpoints = [
        {
            "endpoint_key": "a",
            "resource_group": "users",
            "host": "app.example.com",
            "signals": ["idor"],
            "url": "https://app.example.com/users/1",
            "decision": "HIGH",
            "score": 10,
            "score_breakdown": [],
        },
        {
            "endpoint_key": "b",
            "resource_group": "users",
            "host": "app.example.com",
            "signals": ["idor", "access_control"],
            "url": "https://app.example.com/users/2",
            "decision": "MEDIUM",
            "score": 4,
            "score_breakdown": [],
        },
    ]
    _apply_cross_endpoint_correlation(endpoints)
    assert endpoints[0]["cross_endpoint_correlations"]
    assert endpoints[0]["correlation_score_bonus"] >= 0
    assert endpoints[1]["score"] >= 4
