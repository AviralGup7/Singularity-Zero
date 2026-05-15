"""Endpoint appears accessible without auth context spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("same_status") and item.get("json_accessible") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Confirm from a clean client whether the same read-only endpoint returns substantially the same data shape and identifiers without cookies or auth headers."


register_spec(
    (
        "unauth_access_check",
        "authentication_bypass",
        _severity,
        "Endpoint appears accessible without auth context",
        _description,
    )
)
