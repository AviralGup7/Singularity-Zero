"""Merge sensitive data findings into unified findings list."""

from typing import Any

from src.analysis.helpers import build_manual_hint


def merge_sensitive_data(
    analysis_results: dict[str, list[dict[str, Any]]],
    priority_scores: dict[str, int],
    seen: set[tuple[str, str, str, str]],
    findings: list[dict[str, Any]],
) -> None:
    from ._merge import _finding

    for item in analysis_results.get("sensitive_data_scanner", []):
        severity = "critical" if item.get("indicator") == "private_key_block" else "high"
        f = _finding(
            "sensitive_data_scanner",
            "sensitive_data",
            severity,
            f"Sensitive data indicator: {item.get('indicator', 'unknown')}",
            item.get("url", ""),
            item,
            priority_scores.get(item.get("url", ""), 0),
            build_manual_hint("sensitive_data", item.get("url", ""), item),
            seen,
        )
        if f:
            findings.append(f)

    for item in analysis_results.get("sensitive_field_detector", []):
        matched_fields = item.get("matched_fields", [])
        severity = (
            "high"
            if any(
                field.get("classification") in {"api_key", "credential", "ssn"}
                for field in matched_fields
            )
            else "medium"
        )
        f = _finding(
            "sensitive_field_detector",
            "sensitive_data",
            severity,
            "Sensitive JSON field exposure",
            item.get("url", ""),
            item,
            priority_scores.get(item.get("url", ""), 0),
            "Inspect the JSON schema and confirm whether the exposed fields are user-controlled, cross-tenant, or returned without need.",
            seen,
        )
        if f:
            findings.append(f)
