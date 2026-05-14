"""Weak cookie security attributes spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if len(item.get("issues", [])) >= 2 else "low"


def _description(item: dict[str, Any]) -> str:
    return "Review session and auth cookies for missing Secure, HttpOnly, and SameSite protections."


register_spec(
    (
        "cookie_security_checker",
        "misconfiguration",
        _severity,
        "Weak cookie security attributes",
        _description,
    )
)
