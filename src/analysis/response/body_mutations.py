"""POST body mutation helpers for response analysis.

Contains functions for JSON type detection, field extraction, body field
inference, and POST body mutation generation including privilege escalation
and nested object mutations.
Extracted from response_analysis_mutations.py for better separation of concerns.
"""

import json
from typing import Any

NOISE_FIELD_NAMES = {
    "id",
    "uuid",
    "created_at",
    "updated_at",
    "timestamp",
    "ts",
    "request_id",
    "trace_id",
}


def json_type_name(value: Any) -> str:
    """Return the JSON type name for a Python value."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def extract_fields_recursive(
    data: Any,
    fields: list[tuple[str, str]],
    seen: set[str],
    *,
    depth: int,
    max_depth: int,
    prefix: str = "",
) -> None:
    """Recursively extract field names and types from nested JSON structures."""
    if depth > max_depth:
        return
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in NOISE_FIELD_NAMES:
                continue
            field_key = f"{prefix}.{key}" if prefix else key
            if field_key not in seen:
                seen.add(field_key)
                fields.append((field_key, json_type_name(value)))
                if isinstance(value, dict):
                    extract_fields_recursive(
                        value, fields, seen, depth=depth + 1, max_depth=max_depth, prefix=field_key
                    )
                elif isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
                    extract_fields_recursive(
                        value[0],
                        fields,
                        seen,
                        depth=depth + 1,
                        max_depth=max_depth,
                        prefix=f"{field_key}[]",
                    )
    elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        for key, value in data[0].items():
            if key.lower() in NOISE_FIELD_NAMES:
                continue
            field_key = f"{prefix}.{key}" if prefix else key
            if field_key not in seen:
                seen.add(field_key)
                fields.append((field_key, json_type_name(value)))


def infer_body_fields(body_text: str) -> list[tuple[str, str]]:
    """Infer likely POST body field names and types from response JSON."""
    fields: list[tuple[str, str]] = []
    seen: set[str] = set()
    try:
        extract_fields_recursive(json.loads(body_text), fields, seen, depth=0, max_depth=3)
    except (json.JSONDecodeError, TypeError, KeyError):
        pass
    return fields


def post_body_mutations(field_name: str, field_type: str) -> list[dict[str, Any]]:
    """Generate POST body mutation payloads for a given field."""
    mutations: list[dict[str, Any]] = []
    lowered = field_name.lower()
    if field_type == "string":
        mutations.append({"strategy": "type_confusion_string_to_int", "body": {field_name: 0}})
        mutations.append({"strategy": "type_confusion_string_to_bool", "body": {field_name: True}})
    elif field_type == "integer":
        mutations.append({"strategy": "type_confusion_int_to_string", "body": {field_name: "0"}})
        mutations.append({"strategy": "type_confusion_int_to_float", "body": {field_name: 0.0}})
    elif field_type == "boolean":
        mutations.append(
            {"strategy": "type_confusion_bool_to_string", "body": {field_name: "true"}}
        )
        mutations.append({"strategy": "type_confusion_bool_to_int", "body": {field_name: 1}})
    elif field_type == "array":
        mutations.append({"strategy": "type_confusion_array_to_string", "body": {field_name: "[]"}})
        mutations.append({"strategy": "type_confusion_array_to_object", "body": {field_name: {}}})
    elif field_type == "object":
        mutations.append({"strategy": "type_confusion_object_to_array", "body": {field_name: []}})
        mutations.append(
            {"strategy": "type_confusion_object_to_string", "body": {field_name: "{}"}}
        )
    mutations.append({"strategy": "null_injection", "body": {field_name: None}})
    if field_type in ("object", "array", "string"):
        mutations.append(
            {"strategy": "prototype_pollution_proto", "body": {"__proto__": {"polluted": True}}}
        )
        mutations.append(
            {
                "strategy": "prototype_pollution_constructor",
                "body": {"constructor": {"prototype": {"polluted": True}}},
            }
        )
    if field_type in ("integer", "float"):
        mutations.append({"strategy": "boundary_zero", "body": {field_name: 0}})
        mutations.append({"strategy": "boundary_negative", "body": {field_name: -1}})
        mutations.append({"strategy": "boundary_max_int", "body": {field_name: 2147483647}})
    if lowered in {"role", "roles", "scope", "permission", "permissions", "is_admin", "admin"}:
        mutations.append({"strategy": "privilege_escalation_admin", "body": {field_name: "admin"}})
        mutations.append(
            {"strategy": "privilege_escalation_superadmin", "body": {field_name: "superadmin"}}
        )
        mutations.append({"strategy": "privilege_escalation_root", "body": {field_name: "root"}})
    if lowered in {
        "redirect",
        "redirect_url",
        "return_url",
        "next",
        "return_to",
        "callback",
        "continue",
    }:
        mutations.append(
            {"strategy": "open_redirect_external", "body": {field_name: "https://evil.com"}}
        )
        mutations.append(
            {"strategy": "open_redirect_protocol", "body": {field_name: "javascript:alert(1)"}}
        )
        mutations.append(
            {"strategy": "open_redirect_scheme_relative", "body": {field_name: "//evil.com"}}
        )
    if lowered in {"email", "username", "user", "login"}:
        mutations.append(
            {"strategy": "injection_xss", "body": {field_name: "<script>alert(1)</script>"}}
        )
        mutations.append({"strategy": "injection_sqli", "body": {field_name: "' OR 1=1 --"}})
    if lowered in {"id", "user_id", "account_id", "org_id", "tenant_id"}:
        mutations.append({"strategy": "mass_assignment_id_override", "body": {field_name: 1}})
        mutations.append({"strategy": "mass_assignment_id_zero", "body": {field_name: 0}})
    if field_type == "string":
        mutations.append(
            {"strategy": "array_injection", "body": {field_name: ["value1", "value2"]}}
        )
        mutations.append({"strategy": "empty_string", "body": {field_name: ""}})
        mutations.append({"strategy": "whitespace_only", "body": {field_name: "   "}})
    mutations.append({"strategy": "empty_object_injection", "body": {field_name: {}}})
    mutations.append({"strategy": "empty_array_injection", "body": {field_name: []}})
    seen: set[str] = set()
    unique_mutations: list[dict[str, Any]] = []
    for m in mutations:
        if m["strategy"] not in seen:
            seen.add(m["strategy"])
            unique_mutations.append(m)
    return unique_mutations[:8]


def multi_field_privilege_mutations(priv_fields: dict[str, str]) -> list[dict[str, Any]]:
    """Generate multi-field mutation payloads for privilege escalation testing."""
    mutations: list[dict[str, Any]] = []
    priv_body: dict[str, Any] = {}
    for name, ftype in priv_fields.items():
        lowered = name.lower()
        if lowered in {"role", "scope"}:
            priv_body[name] = "admin"
        elif lowered in {"is_admin", "admin"}:
            priv_body[name] = True
        elif lowered in {"permissions"}:
            priv_body[name] = ["read", "write", "delete", "admin"]
        elif lowered.endswith("_id"):
            priv_body[name] = 1
        else:
            priv_body[name] = "admin"
    mutations.append({"strategy": "multi_field_full_privilege_escalation", "body": priv_body})
    partial_body: dict[str, Any] = {}
    for name, ftype in priv_fields.items():
        lowered = name.lower()
        if lowered in {"role", "scope"}:
            partial_body[name] = "superadmin"
        elif lowered.endswith("_id"):
            partial_body[name] = 0
    if len(partial_body) >= 2:
        mutations.append({"strategy": "multi_field_partial_escalation", "body": partial_body})
    confusion_body: dict[str, Any] = {}
    for name, ftype in priv_fields.items():
        lowered = name.lower()
        if lowered in {"is_admin", "admin"}:
            confusion_body[name] = "true"
        elif lowered in {"role"}:
            confusion_body[name] = 999
        elif lowered.endswith("_id"):
            confusion_body[name] = "admin"
    if confusion_body:
        mutations.append({"strategy": "multi_field_type_confusion", "body": confusion_body})
    array_body: dict[str, Any] = {}
    for name, ftype in priv_fields.items():
        lowered = name.lower()
        if lowered in {"role", "permissions", "scope"}:
            array_body[name] = ["admin", "superadmin", "root"]
        elif lowered.endswith("_id"):
            array_body[name] = [1, 2, 3, 999]
    if array_body:
        mutations.append({"strategy": "multi_field_array_injection", "body": array_body})
    return mutations


def nested_object_mutations(field_name: str, field_type: str) -> list[dict[str, Any]]:
    """Generate nested object mutation payloads."""
    mutations: list[dict[str, Any]] = []
    parts = field_name.split(".")
    if len(parts) < 2:
        return mutations

    def build_nested(p: list[str], value: Any) -> dict[str, Any]:
        if len(p) == 1:
            return {p[0]: value}
        return {p[0]: build_nested(p[1:], value)}

    lowered = parts[-1].lower()
    if lowered in {"role", "is_admin", "permissions", "scope", "admin"}:
        mutations.append(
            {"strategy": "nested_privilege_escalation", "body": build_nested(parts, "admin")}
        )
        mutations.append(
            {"strategy": "nested_privilege_boolean_flip", "body": build_nested(parts, True)}
        )
    mutations.append({"strategy": "nested_type_confusion_null", "body": build_nested(parts, None)})
    mutations.append({"strategy": "nested_type_confusion_empty", "body": build_nested(parts, {})})
    mutations.append(
        {"strategy": "nested_array_injection", "body": build_nested(parts, ["admin", 1, None, {}])}
    )
    return mutations
