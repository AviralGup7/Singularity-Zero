"""Merge behavior analysis findings into unified findings list."""

from typing import Any


def merge_behavior(
    analysis_results: dict[str, list[dict[str, Any]]],
    seen: set[tuple[str, str, str, str]],
    findings: list[dict[str, Any]],
) -> None:
    from ._merge import _finding

    for item in analysis_results.get("behavior_analysis_layer", []):
        if item.get("meaningful_difference"):
            severity = (
                "high" if item.get("confirmed") or item.get("impact_level") == "high" else "medium"
            )
            f = _finding(
                "behavior_analysis_layer",
                "behavioral_deviation",
                severity,
                "Confirmed behavioral deviation"
                if item.get("confirmed")
                else "Behavioral deviation under controlled variant",
                item.get("url", ""),
                item,
                int(item.get("impact_score", 0)),
                "Replay the stored single-parameter variant and compare the saved before/after snapshots and flow transition.",
                seen,
            )
            if f:
                findings.append(f)
