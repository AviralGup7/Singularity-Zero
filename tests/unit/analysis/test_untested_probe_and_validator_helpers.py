"""Coverage for probe confidence helpers and validator result builders."""

from __future__ import annotations

import pytest

from src.analysis.helpers._probe_utils import (
    probe_confidence,
    probe_confidence_from_map,
    probe_severity,
    probe_severity_from_map,
)
from src.core.capabilities import CapabilityManifest, SystemPluginManifest, ToolExecutionContext
from src.core.utils.validator_helpers import (
    SCHEMA_VERSION,
    build_manual_hint,
    build_validator_result,
    classify_object_family,
    json_type_name,
    normalize_headers,
)


@pytest.mark.unit
def test_probe_confidence_defaults_without_map() -> None:
    assert probe_confidence(["x"]) == 0.5
    assert probe_confidence(["x"], confidence_map={"x": 0.8}) == probe_confidence_from_map(
        ["x"], {"x": 0.8}
    )


@pytest.mark.unit
def test_probe_confidence_from_map_adds_bonus_and_caps() -> None:
    cmap = {"a": 0.7, "b": 0.9}
    assert probe_confidence_from_map([], cmap) == 0.5
    scored = probe_confidence_from_map(["a", "b", "c"], cmap, cap=0.95)
    assert 0.9 <= scored <= 0.95


@pytest.mark.unit
def test_probe_severity_from_map_picks_highest() -> None:
    smap = {"a": "low", "b": "critical", "c": "medium"}
    assert probe_severity_from_map(["a", "b"], smap) == "critical"
    assert probe_severity_from_map([], smap) == "low"
    assert probe_severity(["a"], severity_map=smap) == "low"
    assert probe_severity(["missing"]) == "low"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "null"),
        (True, "boolean"),
        (False, "boolean"),
        (3, "integer"),
        (1.5, "float"),
        ("x", "string"),
        ([1], "array"),
        ({"a": 1}, "object"),
        (object(), "unknown"),
    ],
)
def test_json_type_name(value, expected: str) -> None:
    assert json_type_name(value) == expected


@pytest.mark.unit
def test_normalize_headers_lowercases_keys() -> None:
    headers = normalize_headers({"headers": {"Content-Type": "application/json", "X-A": 1}})
    assert headers == {"content-type": "application/json", "x-a": "1"}
    assert normalize_headers({}) == {}


@pytest.mark.unit
def test_build_validator_result_is_canonical() -> None:
    result = build_validator_result(
        module="idor",
        category="idor",
        url="https://api.example.com/api/v1/users?id=1",
        score=80,
        confidence=0.8123,
        signals=["a", "a", "", "b"],
        validation_state="confirmed",
        hint_message="check",
        extra_flag=True,
    )
    assert result["schema_version"] == SCHEMA_VERSION
    assert result["signals"] == ["a", "b"]
    assert result["confidence"] == 0.81
    assert result["endpoint_type"] == "API"
    assert result["extra_flag"] is True
    assert result["auth_flow_endpoint"] is False


@pytest.mark.unit
@pytest.mark.parametrize(
    ("category", "evidence", "needle"),
    [
        ("open_redirect", {"signals": ["same_host_redirect"]}, "/admin"),
        ("open_redirect", {}, "scheme-relative"),
        ("ssrf", {"validation_state": "active_ready"}, "callback host"),
        ("ssrf", {}, "localhost"),
        ("idor", {"comparison": True}, "lower-privileged"),
        ("idor", {}, "one identifier"),
        ("token_leak", {"location": "response_body"}, "rendered response"),
        ("token_leak", {}, "redirects"),
        ("anomaly", {}, "debug-only"),
    ],
)
def test_build_manual_hint_category_copy(category: str, evidence: dict, needle: str) -> None:
    hint = build_manual_hint(category, "https://api.example.com/v1/item", evidence)
    assert needle in hint


@pytest.mark.unit
def test_build_manual_hint_api_fallback() -> None:
    hint = build_manual_hint("unknown", "https://api.example.com/api/v1/x")
    assert "parameter mutations" in hint


@pytest.mark.unit
@pytest.mark.parametrize(
    ("url", "family"),
    [
        ("https://a.com/uploads/1", "uploaded_object"),
        ("https://a.com/users/42", "user_object"),
        ("https://a.com/orders/9", "business_object"),
        ("https://a.com/about", "generic_object"),
    ],
)
def test_classify_object_family(url: str, family: str) -> None:
    assert classify_object_family(url) == family


@pytest.mark.unit
def test_capability_dataclasses_are_frozen() -> None:
    ctx = ToolExecutionContext(env={"A": "1"})
    manifest = CapabilityManifest(
        estimated_duration_seconds=1.0,
        memory_mb=64.0,
        network_calls_per_target=2,
        supports_checkpoint_resume=True,
    )
    plugin = SystemPluginManifest(providers={"scanner": [{"key": "x"}]})
    assert ctx.env["A"] == "1"
    assert manifest.supports_checkpoint_resume is True
    dumped = plugin.to_dict()
    assert dumped["providers"]["scanner"][0]["key"] == "x"
    assert dumped["plugin_schema_version"] == "1.0"
    with pytest.raises(Exception):
        ctx.env = {}  # type: ignore[misc]
