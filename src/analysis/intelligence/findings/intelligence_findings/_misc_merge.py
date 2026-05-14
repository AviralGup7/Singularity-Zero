"""Miscellaneous findings merger for standard analysis modules."""

from typing import Any

from ._merge import _finding
from .specs import get_all_specs


def merge_misc_findings(
    analysis_results: dict[str, list[dict[str, Any]]],
    priority_scores: dict[str, int],
    seen: set[tuple[str, str, str, str]],
) -> list[dict[str, Any]]:
    """Merge findings from standard analysis modules."""
    findings: list[dict[str, Any]] = []
    for module, category, severity_fn, title, next_step_fn in get_all_specs():
        for item in analysis_results.get(module, []):
            findings.append(
                _finding(
                    module,
                    category,
                    severity_fn(item),
                    title,
                    item.get("url", ""),
                    item,
                    priority_scores.get(item.get("url", ""), 0),
                    next_step_fn(item),
                    seen,
                )
            )
    return findings
