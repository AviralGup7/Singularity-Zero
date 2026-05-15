"""Response structure validation and drift detection."""

from statistics import median
from typing import Any

from src.analysis.helpers import endpoint_base_key, endpoint_signature
from src.analysis.json.support import (
    ID_FIELD_RE,
    ROLE_FIELD_TOKENS,
    SENSITIVE_FIELD_TOKENS,
    parse_json_payload,
    summarize_json_payload,
)
from src.analysis.passive.runtime import extract_key_fields


def response_structure_validator(
    responses: list[dict[str, Any]], limit: int = 30
) -> list[dict[str, Any]]:
    """Validate JSON response structure consistency across repeated requests."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        payload = parse_json_payload(response)
        if payload is None:
            continue
        summary = summarize_json_payload(payload)
        base_key = endpoint_base_key(url)
        grouped.setdefault(base_key, []).append(
            {
                "url": url,
                "response": response,
                "summary": summary,
            }
        )

    findings: list[dict[str, Any]] = []
    for base_key, items in grouped.items():
        if len(items) < 2:
            continue

        all_field_sets: list[set[str]] = []
        all_key_fields: list[set[str]] = []
        for item in items:
            field_names = set(item["summary"]["field_names"])
            key_fields = set(extract_key_fields(item["response"].get("body_text") or ""))
            all_field_sets.append(field_names)
            all_key_fields.append(key_fields)

        common_fields = set.intersection(*all_field_sets) if all_field_sets else set()
        all_fields = set.union(*all_field_sets) if all_field_sets else set()
        drifting_fields = all_fields - common_fields
        common_key_fields = set.intersection(*all_key_fields) if all_key_fields else set()
        drifting_key_fields = set.union(*all_key_fields) - common_key_fields

        total_unique = len(all_fields)
        drift_ratio = len(drifting_fields) / total_unique if total_unique > 0 else 0.0
        key_drift_ratio = (
            len(drifting_key_fields) / len(set.union(*all_key_fields)) if all_key_fields else 0.0
        )

        sensitive_drift = [
            f
            for f in drifting_fields
            if any(token in f.lower() for token in SENSITIVE_FIELD_TOKENS)
        ]
        id_drift = [f for f in drifting_fields if ID_FIELD_RE.search(f)]
        role_drift = [
            f for f in drifting_fields if any(token in f.lower() for token in ROLE_FIELD_TOKENS)
        ]

        body_lengths = [
            int(item["response"].get("body_length", len(item["response"].get("body_text", ""))))
            for item in items
        ]
        if body_lengths:
            median_length = median(body_lengths)
            max_deviation = max(abs(length - median_length) for length in body_lengths)
            size_variance_ratio = max_deviation / median_length if median_length > 0 else 0.0
        else:
            size_variance_ratio = 0.0
            median_length = 0

        severity = "info"
        signals = []

        if drift_ratio > 0.3:
            severity = "medium"
            signals.append("high_field_drift")
        if drift_ratio > 0.5:
            severity = "high"
            signals.append("very_high_field_drift")
        if sensitive_drift:
            severity = "high"
            signals.append("sensitive_field_drift")
        if id_drift:
            signals.append("id_field_drift")
        if role_drift:
            signals.append("role_field_drift")
        if size_variance_ratio > 0.5:
            signals.append("response_size_variance")
        if key_drift_ratio > 0.3:
            signals.append("key_field_drift")

        if not signals:
            continue

        drift_sample_urls = []
        for item in items:
            field_names = set(item["summary"]["field_names"])
            if field_names & drifting_fields:
                drift_sample_urls.append(item["url"])

        findings.append(
            {
                "endpoint_base_key": base_key,
                "url": items[0]["url"],
                "endpoint_key": endpoint_signature(items[0]["url"]),
                "response_count": len(items),
                "total_unique_fields": total_unique,
                "common_fields_count": len(common_fields),
                "drifting_fields_count": len(drifting_fields),
                "drift_ratio": round(drift_ratio, 3),
                "key_field_drift_ratio": round(key_drift_ratio, 3),
                "size_variance_ratio": round(size_variance_ratio, 3),
                "median_body_length": int(median_length),
                "severity": severity,
                "signals": signals,
                "drifting_fields": sorted(drifting_fields)[:20],
                "sensitive_drifting_fields": sorted(sensitive_drift)[:10],
                "id_drifting_fields": sorted(id_drift)[:5],
                "role_drifting_fields": sorted(role_drift)[:5],
                "drift_sample_urls": drift_sample_urls[:6],
                "explanation": _build_structure_validation_explanation(
                    base_key,
                    len(items),
                    drift_ratio,
                    sensitive_drift,
                    id_drift,
                    role_drift,
                    size_variance_ratio,
                ),
            }
        )

    findings.sort(
        key=lambda item: (
            item["severity"] not in ("high", "medium"),
            -item["drift_ratio"],
            -item["response_count"],
            item["endpoint_base_key"],
        )
    )
    return findings[:limit]


def _build_structure_validation_explanation(
    base_key: str,
    response_count: int,
    drift_ratio: float,
    sensitive_drift: list[str],
    id_drift: list[str],
    role_drift: list[str],
    size_variance_ratio: float,
) -> str:
    """Build human-readable explanation for structure validation findings."""
    parts = [f"JSON response structure drifts across {response_count} responses at {base_key}."]
    parts.append(f"Field drift ratio: {drift_ratio * 100:.0f}%.")
    if sensitive_drift:
        parts.append(f"Sensitive fields appear conditionally: {', '.join(sensitive_drift[:3])}.")
    if id_drift:
        parts.append(f"ID fields drift: {', '.join(id_drift[:3])}.")
    if role_drift:
        parts.append(f"Role-related fields drift: {', '.join(role_drift[:3])}.")
    if size_variance_ratio > 0.5:
        parts.append(f"Response size variance: {size_variance_ratio * 100:.0f}%.")
    parts.append("This suggests role-based or context-dependent field exposure.")
    return " ".join(parts)
