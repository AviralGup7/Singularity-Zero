"""Role-based response difference detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("response_diff_strength") == "high" else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Compare existing user and admin-style variants for the same endpoint and verify whether the difference matches the intended authorization model."


register_spec(
    (
        "role_based_endpoint_comparison",
        "access_control",
        _severity,
        "Role-based response difference detected",
        _description,
    )
)
