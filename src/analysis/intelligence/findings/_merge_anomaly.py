"""Merge anomaly findings into unified findings list."""

from typing import Any

from src.analysis.helpers import build_manual_hint


def merge_anomaly(
    analysis_results: dict[str, list[dict[str, Any]]],
    priority_scores: dict[str, int],
    seen: set[tuple[str, str, str, str]],
    findings: list[dict[str, Any]],
) -> None:
    from ._merge import _finding

    for item in analysis_results.get("anomaly_detector", []):
        f = _finding(
            "anomaly_detector",
            "anomaly",
            "medium" if item.get("score", 0) >= 3 else "low",
            "Unusual endpoint or response pattern",
            item.get("url", ""),
            item,
            priority_scores.get(item.get("url", ""), 0),
            build_manual_hint("anomaly", item.get("url", ""), item),
            seen,
        )
        if f:
            findings.append(f)
