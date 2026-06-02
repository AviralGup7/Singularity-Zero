"""Merge token leak findings into unified findings list."""

from typing import Any

from src.analysis.helpers import build_manual_hint


def merge_token(
    analysis_results: dict[str, list[dict[str, Any]]],
    priority_scores: dict[str, int],
    anomaly_keys: set[str],
    seen: set[tuple[str, str, str, str]],
    findings: list[dict[str, Any]],
) -> None:
    from src.analysis.helpers import token_location_severity

    from ._merge import _finding, _with_anomaly

    for item in analysis_results.get("token_leak_detector", []):
        item = _with_anomaly(item, anomaly_keys)
        f = _finding(
            "token_leak_detector",
            "token_leak",
            token_location_severity(str(item.get("location", ""))),
            f"Token exposure via {item.get('location', 'unknown')}",
            item.get("url", ""),
            item,
            priority_scores.get(item.get("url", ""), 0),
            build_manual_hint("token_leak", item.get("url", ""), item),
            seen,
        )
        if f:
            findings.append(f)
