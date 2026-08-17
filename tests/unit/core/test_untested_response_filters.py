"""Matrix coverage for classify_response_delta (previously untested)."""

from __future__ import annotations

import pytest

from src.core.utils.response_filters import classify_response_delta


def _classify(**kwargs):
    defaults = {
        "original_status": 200,
        "mutated_status": 200,
        "body_similarity": 1.0,
        "length_delta": 0,
        "redirect_changed": False,
    }
    defaults.update(kwargs)
    return classify_response_delta(**defaults)


@pytest.mark.unit
def test_identical_responses_are_ignored() -> None:
    result = _classify()
    assert result["classification"] == "ignore"
    assert result["include"] is False
    assert result["score"] == 0


@pytest.mark.unit
def test_none_statuses_treated_as_zero() -> None:
    result = _classify(original_status=None, mutated_status=None, body_similarity=0.99)
    assert result["classification"] == "ignore"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("from_status", "to_status", "expected"),
    [
        (200, 403, "auth_enforcement_change"),
        (200, 302, "redirect_gate_change"),
        (401, 200, "auth_bypass_indicator"),
        (403, 200, "auth_bypass_indicator"),
        (401, 500, "auth_bypass_via_error"),
        (403, 500, "auth_bypass_via_error"),
        (200, 500, "server_error_trigger"),
        (200, 405, "method_not_allowed"),
        (200, 429, "rate_limit_triggered"),
    ],
)
def test_high_signal_status_transitions(from_status: int, to_status: int, expected: str) -> None:
    result = _classify(original_status=from_status, mutated_status=to_status)
    assert result["classification"] == expected
    assert result["include"] is True
    assert int(result["score"]) >= 4


@pytest.mark.unit
@pytest.mark.parametrize("to_status", [400, 404])
def test_validation_noise_for_similar_client_errors(to_status: int) -> None:
    result = _classify(mutated_status=to_status, body_similarity=0.95, length_delta=10)
    assert result["classification"] == "validation_noise"
    assert result["score"] == 1


@pytest.mark.unit
@pytest.mark.parametrize("to_status", [403, 406])
def test_waf_block_pattern_on_near_identical_bodies(to_status: int) -> None:
    result = _classify(original_status=201, mutated_status=to_status, body_similarity=0.97)
    assert result["classification"] == "waf_block_pattern"


@pytest.mark.unit
@pytest.mark.parametrize("to_status", [502, 503, 504])
def test_cdn_error_pattern(to_status: int) -> None:
    result = _classify(mutated_status=to_status, body_similarity=0.95)
    assert result["classification"] == "cdn_error_pattern"
    assert result["score"] == 2


@pytest.mark.unit
def test_generic_status_change() -> None:
    result = _classify(original_status=200, mutated_status=201, body_similarity=1.0)
    assert result["classification"] == "status_change"
    assert "201" in str(result["reason"])


@pytest.mark.unit
def test_redirect_destination_change() -> None:
    result = _classify(redirect_changed=True)
    assert result["classification"] == "redirect_change"
    assert result["score"] == 4


@pytest.mark.unit
def test_significant_content_change() -> None:
    result = _classify(body_similarity=0.4, length_delta=500)
    assert result["classification"] == "significant_content_change"
    assert result["score"] == 6


@pytest.mark.unit
def test_content_change_threshold() -> None:
    result = _classify(body_similarity=0.9, length_delta=80)
    assert result["classification"] == "content_change"


@pytest.mark.unit
def test_minor_content_change() -> None:
    result = _classify(body_similarity=0.97, length_delta=20)
    assert result["classification"] == "minor_content_change"
    assert result["score"] == 2


@pytest.mark.unit
def test_score_is_int_and_reason_is_str() -> None:
    result = _classify(mutated_status=500)
    assert isinstance(result["score"], int)
    assert isinstance(result["reason"], str)
    assert isinstance(result["include"], bool)
