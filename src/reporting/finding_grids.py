"""HTML finding grid layout helpers for reporting."""

from __future__ import annotations

import html
from typing import Any

from src.execution.validators.api_test_integration import build_api_test_result


def observed_result_grid(item: dict[str, Any]) -> str:
    """Build observed API replay results grid."""
    result = build_api_test_result(item)
    metric_specs = [
        ("Baseline", result.get("baseline_url", "") or "n/a"),
        ("Variant URL", result.get("variant_url", "") or "n/a"),
        ("Mutation", f"{result.get('parameter', 'n/a')}={result.get('variant', 'n/a')}"),
    ]

    summary_map: dict[str, str] = {}
    for line in str(result.get("summary", "")).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        summary_map[key.strip()] = value.strip()

    metric_specs.extend(
        [
            ("Method", summary_map.get("Observed Method", "n/a")),
            ("Status Changed", summary_map.get("Status Changed", "unknown")),
            ("Content Changed", summary_map.get("Content Changed", "unknown")),
            ("Redirect Changed", summary_map.get("Redirect Changed", "unknown")),
            ("Body Similarity", summary_map.get("Body Similarity", "n/a")),
            ("Length Delta", summary_map.get("Length Delta", "n/a")),
            ("Shared Fields", summary_map.get("Shared Key Fields", "none")),
            ("Replay ID", summary_map.get("Replay ID", "n/a")),
        ]
    )

    cells = "".join(
        "<div class='finding-metric'>"
        f"<strong>{html.escape(label)}</strong>{html.escape(value)}"
        "</div>"
        for label, value in metric_specs
    )
    return f"<div class='finding-grid'>{cells}</div>"


def review_summary_grid(item: dict[str, Any]) -> str:
    """Build review summary metrics grid."""
    metric_specs = [
        ("Type", str(item.get("category", "review")).replace("_", " ")),
        ("Endpoint", str(item.get("endpoint_type", "GENERAL"))),
        ("Confidence", f"{round(float(item.get('confidence', 0)) * 100)}%"),
        ("Status", str(item.get("history_status", "new"))),
    ]
    if item.get("combined_signal"):
        metric_specs.append(("Signal", str(item.get("combined_signal", "none"))))
    cells = "".join(
        "<div class='finding-metric'>"
        f"<strong>{html.escape(label)}</strong>{html.escape(value)}"
        "</div>"
        for label, value in metric_specs
    )
    return f"<div class='finding-grid'>{cells}</div>"
