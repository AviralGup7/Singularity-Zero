"""Coverage for CVSS scoring and analysis helper shims."""

from __future__ import annotations

import pytest

from src.analysis.helpers._classification import (
    build_endpoint_meta,
    ensure_endpoint_key,
    is_backup_endpoint,
    is_debug_endpoint,
    is_exposed_spec_endpoint,
    is_self_endpoint,
    resolve_endpoint_key,
)
from src.analysis.helpers.response_filters import classify_response_delta
from src.analysis.intelligence.cvss_scoring import (
    CATEGORY_CVSS_DEFAULTS,
    CVSSScore,
    _calculate_cvss_base_score,
    _severity_from_score,
    score_finding_cvss,
)
from src.detection.signals import compose_signals


@pytest.mark.unit
@pytest.mark.parametrize("category", sorted(CATEGORY_CVSS_DEFAULTS))
def test_every_default_category_produces_valid_cvss(category: str) -> None:
    score = score_finding_cvss(category)
    assert isinstance(score, CVSSScore)
    assert score.vector_string.startswith("CVSS:3.1/")
    assert 0.0 <= score.base_score <= 10.0
    assert score.severity in {"none", "low", "medium", "high", "critical"}
    assert score.explanation


@pytest.mark.unit
def test_unknown_category_still_scores() -> None:
    score = score_finding_cvss("totally_unknown_category")
    assert score.vector_string.startswith("CVSS:3.1/")
    assert "totally_unknown_category" in score.explanation


@pytest.mark.unit
def test_auth_required_raises_privileges_from_none() -> None:
    baseline = score_finding_cvss("ssrf")
    adjusted = score_finding_cvss("ssrf", auth_required=True)
    assert baseline.privileges_required == "N"
    assert adjusted.privileges_required == "L"


@pytest.mark.unit
def test_user_interaction_flag_sets_required() -> None:
    baseline = score_finding_cvss("idor")
    adjusted = score_finding_cvss("idor", user_interaction=True)
    assert baseline.user_interaction == "N"
    assert adjusted.user_interaction == "R"


@pytest.mark.unit
def test_scope_change_and_high_confidence_evidence() -> None:
    score = score_finding_cvss(
        "misconfiguration",
        confidence=0.95,
        evidence={"reproducible": True, "trust_boundary_shift": True, "signals": ["a", "b", "c"]},
    )
    assert score.scope == "C"
    assert score.confidentiality == "H"
    assert score.availability in {"L", "H"}


@pytest.mark.unit
def test_auth_bypass_evidence_drops_required_privileges() -> None:
    score = score_finding_cvss("access_control", evidence={"auth_bypass_variant": True})
    assert score.integrity == "H"
    assert score.privileges_required == "N"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "label"),
    [(0.0, "none"), (1.0, "low"), (3.9, "low"), (4.0, "medium"), (7.0, "high"), (9.0, "critical")],
)
def test_severity_from_score_buckets(value: float, label: str) -> None:
    assert _severity_from_score(value) == label


@pytest.mark.unit
def test_zero_impact_base_score_is_zero() -> None:
    assert _calculate_cvss_base_score("N", "L", "N", "N", "U", "N", "N", "N") == 0.0


@pytest.mark.unit
def test_helper_reexport_matches_core_classifier() -> None:
    kwargs = {
        "original_status": 401,
        "mutated_status": 200,
        "body_similarity": 0.5,
        "length_delta": 10,
        "redirect_changed": False,
    }
    assert classify_response_delta(**kwargs)["classification"] == "auth_bypass_indicator"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("url", "fn", "expected"),
    [
        ("https://api.example.com/users/me", is_self_endpoint, True),
        ("https://api.example.com/account", is_self_endpoint, True),
        ("https://api.example.com/users/42", is_self_endpoint, False),
        ("https://app.example.com/actuator/env", is_debug_endpoint, True),
        ("https://app.example.com/health", is_debug_endpoint, True),
        ("https://app.example.com/about", is_debug_endpoint, False),
        ("https://app.example.com/backup.sql", is_backup_endpoint, True),
        ("https://app.example.com/openapi.json", is_exposed_spec_endpoint, True),
        ("https://app.example.com/swagger", is_exposed_spec_endpoint, True),
        ("https://app.example.com/about", is_exposed_spec_endpoint, False),
    ],
)
def test_endpoint_classifiers(url: str, fn, expected: bool) -> None:
    assert fn(url) is expected


@pytest.mark.unit
def test_build_and_resolve_endpoint_meta() -> None:
    url = "https://api.example.com/v1/users?id=1"
    meta = build_endpoint_meta(url)
    assert set(meta) == {"endpoint_key", "endpoint_base_key", "endpoint_type"}
    assert all(meta.values())
    item = {"url": url, **meta}
    assert resolve_endpoint_key(item) == meta["endpoint_key"]
    assert ensure_endpoint_key({}, url) == meta["endpoint_key"]


@pytest.mark.unit
def test_compose_signals_dedupes_and_drops_empty() -> None:
    assert compose_signals(" xss ", None, ["xss", "sqli", None, ""], ("sqli", "idor")) == [
        "idor",
        "sqli",
        "xss",
    ]


@pytest.mark.unit
def test_compose_signals_empty_input() -> None:
    assert compose_signals() == []
    assert compose_signals(None, "", [], set()) == []
