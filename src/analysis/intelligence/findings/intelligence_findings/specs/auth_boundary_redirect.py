"""Redirect crosses auth boundary spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if item.get("boundary_changed") else "low"


def _description(item: dict[str, Any]) -> str:
    return "Compare the pre-login and post-login redirect destinations to confirm whether auth context changes the redirect target or trust boundary."


register_spec(
    (
        "auth_boundary_redirect_detection",
        "redirect",
        _severity,
        "Redirect crosses auth boundary",
        _description,
    )
)
