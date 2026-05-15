"""Merge open redirect findings into unified findings list."""

from typing import Any

from src.analysis.helpers import build_manual_hint


def merge_redirect(
    analysis_results: dict[str, list[dict[str, Any]]],
    custom_results: dict[str, Any],
    priority_scores: dict[str, int],
    anomaly_keys: set[str],
    seen: set[tuple[str, str, str, str]],
    findings: list[dict[str, Any]],
) -> None:
    from ._merge import _finding, _with_anomaly

    open_redirect_items = custom_results.get("open_redirect_validation", [])
    for item in open_redirect_items:
        item = _with_anomaly(item, anomaly_keys)
        severity = (
            "high"
            if "cross_host_target" in item.get("signals", [])
            or item.get("validation_state") == "active_ready"
            else "medium"
        )
        category = "oauth_flow" if item.get("auth_flow_endpoint") else "open_redirect"
        title = (
            "Likely OAuth redirect flow"
            if item.get("auth_flow_endpoint")
            else "Likely open redirect flow"
        )
        f = _finding(
            str(item.get("module") or "open_redirect_validation"),
            category,
            severity,
            title,
            item.get("url", ""),
            item,
            priority_scores.get(item.get("url", ""), 0),
            build_manual_hint("open_redirect", item.get("url", ""), item),
            seen,
        )
        if f:
            findings.append(f)
