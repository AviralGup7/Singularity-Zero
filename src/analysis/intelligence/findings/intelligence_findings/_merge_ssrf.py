"""Merge SSRF findings into unified findings list."""

from typing import Any

from src.analysis.helpers import build_manual_hint


def merge_ssrf(
    analysis_results: dict[str, list[dict[str, Any]]],
    custom_results: dict[str, Any],
    priority_scores: dict[str, int],
    anomaly_keys: set[str],
    seen: set[tuple[str, str, str, str]],
    findings: list[dict[str, Any]],
) -> None:
    from ._merge import _finding, _with_anomaly

    ssrf_items = custom_results.get("ssrf_validation") or analysis_results.get(
        "ssrf_candidate_finder", []
    )
    for item in ssrf_items:
        item = _with_anomaly(item, anomaly_keys)
        severity = (
            "high"
            if item.get("validation_state") == "active_ready" or item.get("score", 0) >= 7
            else "medium"
        )
        f = _finding(
            str(item.get("module") or "ssrf_candidate_finder"),
            "ssrf",
            severity,
            "Potential SSRF sink parameter",
            item.get("url", ""),
            item,
            priority_scores.get(item.get("url", ""), 0),
            build_manual_hint("ssrf", item.get("url", ""), item),
            seen,
        )
        if f:
            findings.append(f)
