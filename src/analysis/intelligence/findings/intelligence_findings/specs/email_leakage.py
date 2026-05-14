"""Email address exposure spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "low"


def _description(item: dict[str, Any]) -> str:
    return "Use the exposed addresses for asset correlation, but verify they are in-scope before pivoting."


register_spec(
    (
        "email_leakage_detector",
        "exposure",
        _severity,
        "Email address exposure",
        _description,
    )
)
