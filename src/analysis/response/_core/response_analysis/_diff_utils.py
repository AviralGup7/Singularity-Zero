"""Diff utilities for comparing original and mutated responses."""

import json
import logging
from difflib import SequenceMatcher
from typing import Any

from src.analysis.helpers import NOISE_FIELD_NAMES
from src.analysis.passive.runtime import extract_key_fields, normalize_compare_text
from src.analysis.response.filter_rules import classify_response_delta

from ._similarity import content_type_similarity_threshold

logger = logging.getLogger(__name__)


def _redirect_target(response: dict[str, Any]) -> str:
    headers = {
        str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()
    }
    return headers.get("location", "")


def variant_diff_summary(original: dict[str, Any], mutated: dict[str, Any]) -> dict[str, Any]:
    """Compare original and mutated responses and produce a diff summary."""
    original_body = original.get("body_text") or ""
    mutated_body = mutated.get("body_text") or ""
    original_status = original.get("status_code")
    mutated_status = mutated.get("status_code")
    original_redirect = _redirect_target(original)
    mutated_redirect = _redirect_target(mutated)
    status_changed = original_status != mutated_status
    redirect_changed = original_redirect != mutated_redirect
    length_delta = abs(len(original_body) - len(mutated_body))

    content_type = original.get("content_type", "") or mutated.get("content_type", "")
    similarity_threshold = content_type_similarity_threshold(content_type)

    original_key_fields = extract_key_fields(original_body)
    mutated_key_fields = extract_key_fields(mutated_body)

    if not status_changed and not redirect_changed and original_body == mutated_body:
        json_schema_available = False
        new_fields: list[str] = []
        missing_fields: list[str] = []
        changed_fields: list[dict[str, str]] = []
        parsed = _try_parse_json_payload(original)
        if parsed is not None:
            json_schema_available = True
            flat = _flatten_json_fields(parsed) if isinstance(parsed, dict) else {}
            new_fields = sorted(flat.keys())[:20]
        return {
            "original_status": original_status,
            "mutated_status": mutated_status,
            "body_similarity": 1.0,
            "length_delta": 0,
            "shared_key_fields": sorted(original_key_fields & mutated_key_fields)[:12],
            "status_changed": False,
            "redirect_changed": False,
            "content_changed": False,
            "changed": False,
            "classification": "ignore",
            "score": 0,
            "reason": "Identical responses.",
            "structured_diff_available": json_schema_available,
            "new_fields": new_fields,
            "missing_fields": missing_fields,
            "changed_fields": changed_fields,
            "similarity_threshold": similarity_threshold,
            "timing_delta_ms": None,
        }

    original_normalized = normalize_compare_text(original_body)
    mutated_normalized = normalize_compare_text(mutated_body)

    max_len = max(len(original_normalized), len(mutated_normalized), 1)
    if length_delta > max_len * 0.25:
        similarity = round(max(0.0, 1.0 - (length_delta / max_len)), 3)
        structured_available = False
        new_fields = []
        missing_fields = []
        changed_fields = []
    else:
        structured_diff = _structured_json_diff(original, mutated)
        if structured_diff is None:
            similarity = round(
                SequenceMatcher(None, original_normalized, mutated_normalized).ratio(), 3
            )
            new_fields = []
            missing_fields = []
            changed_fields = []
            structured_available = False
        else:
            similarity = structured_diff["body_similarity"]
            new_fields = structured_diff["new_fields"]
            missing_fields = structured_diff["missing_fields"]
            changed_fields = structured_diff["changed_fields"]
            structured_available = True

    response_filter = classify_response_delta(
        original_status=original_status,
        mutated_status=mutated_status,
        body_similarity=similarity,
        length_delta=length_delta,
        redirect_changed=redirect_changed,
    )

    original_time = original.get("response_time_ms") or original.get("elapsed_ms")
    mutated_time = mutated.get("response_time_ms") or mutated.get("elapsed_ms")
    timing_delta_ms = None
    if original_time is not None and mutated_time is not None:
        try:
            timing_delta_ms = round(float(mutated_time) - float(original_time), 2)
        except (ValueError, TypeError) as exc:
            logger.debug("Ignored: %s", exc)
            timing_delta_ms = None

    return {
        "original_status": original_status,
        "mutated_status": mutated_status,
        "body_similarity": similarity,
        "length_delta": length_delta,
        "shared_key_fields": sorted(original_key_fields & mutated_key_fields)[:12],
        "status_changed": status_changed,
        "redirect_changed": redirect_changed,
        "content_changed": similarity < similarity_threshold
        or length_delta > max(40, int(max(len(original_body), 1) * 0.1)),
        "changed": bool(response_filter["include"]),
        "classification": response_filter["classification"],
        "score": int(float(str(response_filter["score"]))),
        "reason": response_filter["reason"],
        "structured_diff_available": structured_available,
        "new_fields": new_fields,
        "missing_fields": missing_fields,
        "changed_fields": changed_fields,
        "similarity_threshold": similarity_threshold,
        "timing_delta_ms": timing_delta_ms,
    }


def _structured_json_diff(
    original: dict[str, Any], mutated: dict[str, Any]
) -> dict[str, Any] | None:
    original_payload = _try_parse_json_payload(original)
    mutated_payload = _try_parse_json_payload(mutated)
    if original_payload is None or mutated_payload is None:
        return None

    original_fields = _flatten_json_fields(original_payload)
    mutated_fields = _flatten_json_fields(mutated_payload)
    original_keys = set(original_fields)
    mutated_keys = set(mutated_fields)

    new_fields = sorted(mutated_keys - original_keys)
    missing_fields = sorted(original_keys - mutated_keys)
    changed_fields = []
    for key in sorted(original_keys & mutated_keys):
        if original_fields[key] == mutated_fields[key]:
            continue
        changed_fields.append(
            {"field": key, "from": original_fields[key], "to": mutated_fields[key]}
        )

    total = max(1, len(original_keys | mutated_keys))
    change_count = len(new_fields) + len(missing_fields) + len(changed_fields)
    similarity = round(max(0.0, 1.0 - (change_count / total)), 3)
    return {
        "body_similarity": similarity,
        "new_fields": new_fields[:30],
        "missing_fields": missing_fields[:30],
        "changed_fields": changed_fields[:30],
    }


def _try_parse_json_payload(record: dict[str, Any]) -> dict[str, Any] | list[Any] | None:
    from src.analysis.helpers import JSON_CONTENT_TOKENS

    body = str(record.get("body_text") or "").strip()
    if not body:
        return None
    content_type = str(record.get("content_type") or "").lower()
    if not any(token in content_type for token in JSON_CONTENT_TOKENS) and not body.startswith(
        ("{", "[")
    ):
        return None
    try:
        payload = json.loads(body)
    except Exception:
        return None
    if isinstance(payload, (dict, list)):
        return payload
    return None


def _flatten_json_fields(payload: dict[str, Any] | list[Any]) -> dict[str, str]:
    flat: dict[str, str] = {}

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_name = str(key).strip()
                if not key_name:
                    continue
                child_path = f"{path}.{key_name}" if path else key_name
                visit(child, child_path)
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                child_path = f"{path}[{index}]" if path else f"[{index}]"
                visit(child, child_path)
            return
        if not _is_noise_field(path):
            try:
                flat[path] = json.dumps(value, sort_keys=True)
            except TypeError:
                flat[path] = str(value)

    visit(payload, "")
    return flat


def _is_noise_field(path: str) -> bool:
    if not path:
        return False
    base = path.split("[", 1)[0]
    field_name = base.split(".")[-1].strip().lower()
    if field_name in NOISE_FIELD_NAMES:
        return True
    if field_name.endswith("_id"):
        return True
    if field_name.endswith("_timestamp"):
        return True
    return False
