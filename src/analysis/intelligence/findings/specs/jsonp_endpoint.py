"""Legacy JSONP-style endpoint detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return (
        "Review whether the JSONP callback can return user-specific or sensitive data cross-origin."
    )


register_spec(
    (
        "jsonp_endpoint_checker",
        "misconfiguration",
        _severity,
        "Legacy JSONP-style endpoint detected",
        _description,
    )
)
