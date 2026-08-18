"""Coverage for previously untested POST body mutation helpers."""

from __future__ import annotations

import pytest

from src.analysis.response.body_mutations import (
    infer_body_fields,
    json_type_name,
    multi_field_privilege_mutations,
    nested_object_mutations,
    post_body_mutations,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "null"),
        (True, "boolean"),
        (False, "boolean"),
        (7, "integer"),
        (1.5, "float"),
        ("x", "string"),
        ([], "array"),
        ({}, "object"),
        (object(), "unknown"),
    ],
)
def test_json_type_name(value: object, expected: str) -> None:
    assert json_type_name(value) == expected


@pytest.mark.unit
def test_infer_body_fields_skips_noise_and_walks_nested() -> None:
    fields = infer_body_fields(
        '{"id": 1, "name": "a", "meta": {"role": "user"}, "items": [{"price": 2}]}'
    )
    assert ("name", "string") in fields
    assert ("meta", "object") in fields
    assert ("meta.role", "string") in fields
    assert ("items", "array") in fields
    assert ("items[].price", "integer") in fields
    assert all(name != "id" for name, _ in fields)


@pytest.mark.unit
def test_infer_body_fields_invalid_json_is_empty() -> None:
    assert infer_body_fields("not-json") == []
    assert infer_body_fields("") == []


@pytest.mark.unit
def test_post_body_mutations_caps_at_eight_and_dedupes() -> None:
    mutations = post_body_mutations("name", "string")
    strategies = [m["strategy"] for m in mutations]
    assert len(mutations) <= 8
    assert len(strategies) == len(set(strategies))
    assert "type_confusion_string_to_int" in strategies
    assert "null_injection" in strategies


@pytest.mark.unit
@pytest.mark.parametrize(
    ("field_name", "field_type", "required"),
    [
        ("role", "string", "privilege_escalation_admin"),
        ("is_admin", "boolean", "privilege_escalation_root"),
        ("redirect_url", "string", "open_redirect_external"),
        ("email", "string", "injection_xss"),
        ("user_id", "integer", "mass_assignment_id_override"),
        ("count", "integer", "boundary_negative"),
        ("flags", "array", "type_confusion_array_to_object"),
        ("profile", "object", "type_confusion_object_to_array"),
    ],
)
def test_post_body_mutations_include_field_specific_strategies(
    field_name: str, field_type: str, required: str
) -> None:
    strategies = [m["strategy"] for m in post_body_mutations(field_name, field_type)]
    assert required in strategies


@pytest.mark.unit
def test_multi_field_privilege_mutations_cover_admin_and_ids() -> None:
    mutations = multi_field_privilege_mutations(
        {"role": "string", "is_admin": "boolean", "org_id": "integer"}
    )
    strategies = [m["strategy"] for m in mutations]
    assert "multi_field_full_privilege_escalation" in strategies
    full = next(m for m in mutations if m["strategy"] == "multi_field_full_privilege_escalation")
    assert full["body"]["role"] == "admin"
    assert full["body"]["is_admin"] is True
    assert full["body"]["org_id"] == 1
    assert "multi_field_partial_escalation" in strategies
    assert "multi_field_type_confusion" in strategies


@pytest.mark.unit
def test_nested_object_mutations_require_dotted_path() -> None:
    assert nested_object_mutations("role", "string") == []
    nested = nested_object_mutations("user.profile.role", "string")
    strategies = [m["strategy"] for m in nested]
    assert "nested_privilege_escalation" in strategies
    body = next(m["body"] for m in nested if m["strategy"] == "nested_privilege_escalation")
    assert body == {"user": {"profile": {"role": "admin"}}}
    assert "nested_type_confusion_null" in strategies
