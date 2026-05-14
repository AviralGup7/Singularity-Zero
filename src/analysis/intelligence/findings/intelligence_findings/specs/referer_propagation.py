"""Sensitive parameters may propagate through referers spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if item.get("propagation_risk") else "low"


def _description(item: dict[str, Any]) -> str:
    return "Review the referrer policy and outbound links to confirm whether sensitive query data can leak cross-origin."


register_spec(
    (
        "referer_propagation_tracking",
        "token_leak",
        _severity,
        "Sensitive parameters may propagate through referers",
        _description,
    )
)
