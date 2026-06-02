"""Merge SSTI findings into unified findings list."""

from typing import Any


def merge_ssti(
    analysis_results: dict[str, list[dict[str, Any]]],
    priority_scores: dict[str, int],
    seen: set[tuple[str, str, str, str]],
    findings: list[dict[str, Any]],
) -> None:
    from ._merge import _finding

    for item in analysis_results.get("ssti_surface_detector", []):
        severity = item.get("severity", "medium")
        engines = item.get("detected_engines", [])
        title = (
            f"SSTI surface detected: {', '.join(engines)}"
            if engines
            else "Potential SSTI surface detected"
        )
        f = _finding(
            "ssti_surface_detector",
            "ssti",
            severity,
            title,
            item.get("url", ""),
            item,
            priority_scores.get(item.get("url", ""), 0),
            "Review the detected template engine and test with safe SSTI payloads to confirm whether server-side template processing occurs.",
            seen,
        )
        if f:
            findings.append(f)
