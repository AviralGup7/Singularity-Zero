"""Merge IDOR findings into unified findings list."""

from typing import Any

from src.analysis.helpers import build_manual_hint


def merge_idor(
    analysis_results: dict[str, list[dict[str, Any]]],
    custom_results: dict[str, Any],
    priority_scores: dict[str, int],
    anomaly_keys: set[str],
    seen: set[tuple[str, str, str, str]],
    findings: list[dict[str, Any]],
) -> None:
    from ._merge import _finding, _with_anomaly

    idor_items = custom_results.get("idor_validation") or analysis_results.get(
        "idor_candidate_finder", []
    )
    for item in idor_items:
        item = _with_anomaly(item, anomaly_keys)
        severity = "high" if item.get("comparison") else "medium"
        f = _finding(
            str(item.get("module") or "idor_candidate_finder"),
            "idor",
            severity,
            "Potential object reference exposure",
            item.get("url", ""),
            item,
            priority_scores.get(item.get("url", ""), 0),
            build_manual_hint("idor", item.get("url", ""), item),
            seen,
        )
        if f:
            findings.append(f)
