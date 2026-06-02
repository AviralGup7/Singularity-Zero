"""Merge CSRF findings into unified findings list."""

from typing import Any


def merge_csrf(
    analysis_results: dict[str, list[dict[str, Any]]],
    priority_scores: dict[str, int],
    seen: set[tuple[str, str, str, str]],
    findings: list[dict[str, Any]],
) -> None:
    from ._merge import _finding

    for item in analysis_results.get("csrf_protection_checker", []):
        severity = item.get("severity", "medium")
        missing = item.get("missing_protections", [])
        title = (
            f"Missing CSRF protections: {', '.join(missing)}"
            if missing
            else "CSRF protection gap detected"
        )
        f = _finding(
            "csrf_protection_checker",
            "csrf",
            severity,
            title,
            item.get("url", ""),
            item,
            priority_scores.get(item.get("url", ""), 0),
            "Confirm whether the endpoint performs state-changing operations and whether CSRF tokens or SameSite cookies are enforced.",
            seen,
        )
        if f:
            findings.append(f)
