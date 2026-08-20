"""Coverage for auto filters and finding lifecycle (previously untested)."""

from __future__ import annotations

import pytest

from src.core.auto_filters import AutoFilterEngine, FilterRule, create_default_security_filters
from src.core.contracts.finding_lifecycle import (
    FindingLifecycleState,
    apply_lifecycle,
    can_transition,
    infer_lifecycle_state,
    normalize_lifecycle_state,
    transition_state,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("detected", FindingLifecycleState.DETECTED),
        ("VALIDATED", FindingLifecycleState.VALIDATED),
        ("exploitable", FindingLifecycleState.EXPLOITABLE),
        ("reportable", FindingLifecycleState.REPORTABLE),
        ("", FindingLifecycleState.DETECTED),
        (None, FindingLifecycleState.DETECTED),
        ("nope", FindingLifecycleState.DETECTED),
    ],
)
def test_normalize_lifecycle_state(value, expected: FindingLifecycleState) -> None:
    assert normalize_lifecycle_state(value) is expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("current", "target", "allowed"),
    [
        (FindingLifecycleState.DETECTED, FindingLifecycleState.VALIDATED, True),
        (FindingLifecycleState.DETECTED, FindingLifecycleState.EXPLOITABLE, True),
        (FindingLifecycleState.DETECTED, FindingLifecycleState.REPORTABLE, False),
        (FindingLifecycleState.VALIDATED, FindingLifecycleState.REPORTABLE, True),
        (FindingLifecycleState.EXPLOITABLE, FindingLifecycleState.REPORTABLE, True),
        (FindingLifecycleState.REPORTABLE, FindingLifecycleState.DETECTED, False),
        (FindingLifecycleState.VALIDATED, FindingLifecycleState.VALIDATED, True),
    ],
)
def test_can_transition_matrix(
    current: FindingLifecycleState, target: FindingLifecycleState, allowed: bool
) -> None:
    assert can_transition(current, target) is allowed


@pytest.mark.unit
def test_transition_state_from_none_uses_target() -> None:
    assert transition_state(None, "validated") == "validated"


@pytest.mark.unit
def test_illegal_transition_keeps_existing_state() -> None:
    assert transition_state("reportable", "detected") == "reportable"
    assert transition_state("false_positive", "reportable") == "false_positive"


@pytest.mark.unit
def test_infer_lifecycle_reportable_for_kept_critical() -> None:
    assert infer_lifecycle_state({"decision": "KEEP", "severity": "critical"}) == "reportable"


@pytest.mark.unit
def test_infer_lifecycle_exploitable_when_verified() -> None:
    assert infer_lifecycle_state({"verified": True}) == "exploitable"
    assert infer_lifecycle_state({"evidence": {"validation_state": "confirmed"}}) == "exploitable"


@pytest.mark.unit
def test_infer_lifecycle_validated_for_unknown_validation_state() -> None:
    assert infer_lifecycle_state({"validation_state": "manual_review"}) == "validated"


@pytest.mark.unit
def test_infer_lifecycle_detected_default() -> None:
    assert infer_lifecycle_state({}) == "detected"
    assert infer_lifecycle_state({"validation_state": "passive_only"}) == "detected"


@pytest.mark.unit
def test_apply_lifecycle_stamps_state() -> None:
    findings = apply_lifecycle([{"severity": "low"}, {"verified": True}])
    assert findings[0]["lifecycle_state"] == "detected"
    assert findings[1]["lifecycle_state"] == "exploitable"


@pytest.mark.unit
def test_filter_rule_contains_and_inverse() -> None:
    rule = FilterRule("css", "url", "contains", ".css")
    assert rule.matches({"url": "https://a.com/app.CSS"}) is True
    inverse = FilterRule("css", "url", "contains", ".css", inverse=True)
    assert inverse.matches({"url": "https://a.com/app.css"}) is False


@pytest.mark.unit
def test_filter_rule_equals_and_regex_and_headers() -> None:
    assert FilterRule("m", "method", "equals", "get").matches({"method": "GET"}) is True
    assert FilterRule("st", "status", "regex", r"^2\d\d$").matches({"status_code": 200}) is True
    headers_rule = FilterRule("auth", "headers", "contains", "bearer")
    assert headers_rule.matches({"request_headers": {"Authorization": "Bearer x"}}) is True


@pytest.mark.unit
def test_filter_rule_unknown_field_respects_inverse() -> None:
    assert FilterRule("x", "nope", "equals", "z").matches({}) is False
    assert FilterRule("x", "nope", "equals", "z", inverse=True).matches({}) is True


@pytest.mark.unit
def test_engine_and_or_logic() -> None:
    engine = AutoFilterEngine()
    engine.add_rule(FilterRule("api", "url", "contains", "/api"))
    engine.add_rule(FilterRule("get", "method", "equals", "GET"))
    items = [
        {"url": "https://a.com/api", "method": "GET"},
        {"url": "https://a.com/api", "method": "POST"},
        {"url": "https://a.com/home", "method": "GET"},
    ]
    assert len(engine.filter_items(items)) == 1
    engine.set_logic("OR")
    assert len(engine.filter_items(items)) == 3
    with pytest.raises(ValueError):
        engine.set_logic("XOR")


@pytest.mark.unit
def test_default_security_filters_drop_static_health_and_options() -> None:
    engine = create_default_security_filters()
    kept = engine.filter_items(
        [
            {"url": "https://a.com/app.js", "method": "GET"},
            {"url": "https://a.com/health", "method": "GET"},
            {"url": "https://a.com/api/users", "method": "OPTIONS"},
            {"url": "https://a.com/api/users", "method": "GET"},
        ]
    )
    assert kept == [{"url": "https://a.com/api/users", "method": "GET"}]
    engine.clear_rules()
    assert engine.filter_items([{"url": "x"}]) == [{"url": "x"}]
