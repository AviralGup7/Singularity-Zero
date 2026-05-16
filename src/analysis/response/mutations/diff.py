"""Diff utilities for response comparison and JSON flattening."""

import json
from difflib import SequenceMatcher
from typing import Any

from src.analysis.response.filter_rules import classify_response_delta

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


def _flatten_json(data: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten a JSON structure into dot-notation paths."""
    items: dict[str, Any] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                items.update(_flatten_json(value, path))
            elif isinstance(value, list):
                items[path] = value
                for i, item in enumerate(value):
                    if isinstance(item, (dict, list)):
                        items.update(_flatten_json(item, f"{path}[{i}]"))
                    else:
                        items[f"{path}[{i}]"] = item
            else:
                items[path] = value
    else:
        items[prefix] = data
    return items


def _variant_diff_summary(baseline: dict[str, Any], mutated: dict[str, Any]) -> dict[str, Any]:
    baseline_body = str(baseline.get("body_text", ""))
    mutated_body = str(mutated.get("body_text", ""))
    baseline_status = int(baseline.get("status_code") or 0)
    mutated_status = int(mutated.get("status_code") or 0)
    body_similarity = (
        SequenceMatcher(None, baseline_body, mutated_body).ratio()
        if baseline_body or mutated_body
        else 1.0
    )
    status_changed = baseline_status != mutated_status
    content_changed = body_similarity < 0.97
    changed = status_changed or content_changed
    classification = classify_response_delta(
        original_status=baseline_status,
        mutated_status=mutated_status,
        body_similarity=body_similarity,
        length_delta=len(mutated_body) - len(baseline_body),
        redirect_changed=False,
    )
    result: dict[str, Any] = {
        "changed": changed,
        "status_changed": status_changed,
        "content_changed": content_changed,
        "body_similarity": round(body_similarity, 4),
        "original_status": baseline_status,
        "mutated_status": mutated_status,
        "classification": classification,
    }
    try:
        baseline_data = json.loads(baseline_body)
        mutated_data = json.loads(mutated_body)
    except (json.JSONDecodeError, ValueError, TypeError):
        result["structured_diff_available"] = False
        return result
    baseline_flat = _flatten_json(baseline_data)
    mutated_flat = _flatten_json(mutated_data)
    baseline_keys = set(baseline_flat.keys())
    mutated_keys = set(mutated_flat.keys())
    new_fields_list = sorted(mutated_keys - baseline_keys)
    missing_fields_list = sorted(baseline_keys - mutated_keys)
    changed_fields_list = []
    for key in sorted(baseline_keys & mutated_keys):
        if key.split(".")[-1].lower() in NOISE_FIELD_NAMES:
            continue
        if key in (
            "id",
            "uuid",
            "created_at",
            "updated_at",
            "timestamp",
            "ts",
            "request_id",
            "trace_id",
        ):
            continue
        b_val = baseline_flat[key]
        m_val = mutated_flat[key]
        if b_val != m_val:
            changed_fields_list.append({"field": key, "original": b_val, "mutated": m_val})
    result["structured_diff_available"] = True
    result["new_fields"] = [
        f for f in new_fields_list if f.split(".")[-1].lower() not in NOISE_FIELD_NAMES
    ]
    result["missing_fields"] = [
        f for f in missing_fields_list if f.split(".")[-1].lower() not in NOISE_FIELD_NAMES
    ]
    result["changed_fields"] = changed_fields_list
    return result
