"""Response volume anomaly in resource group spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if item.get("anomaly_ratio", 0) >= 5 else "low"


def _description(item: dict[str, Any]) -> str:
    return "Check whether the oversized response corresponds to bulk export, hidden includes, or over-broad object expansion."


register_spec(
    (
        "response_size_anomaly_detector",
        "anomaly",
        _severity,
        "Response volume anomaly in resource group",
        _description,
    )
)
