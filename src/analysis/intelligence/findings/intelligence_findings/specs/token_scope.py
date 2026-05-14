"""Token or scope fields reveal granted privileges spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("admin_scope_hint") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Map the observed token, role, and permission fields to the actual actions or resources they appear to unlock."


register_spec(
    (
        "token_scope_analyzer",
        "token_leak",
        _severity,
        "Token or scope fields reveal granted privileges",
        _description,
    )
)
