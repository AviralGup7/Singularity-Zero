"""Password flow missing confirmation signal spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Review signup or reset flows to ensure password changes require confirmation fields and mismatch handling."


register_spec(
    (
        "password_confirmation_checker",
        "misconfiguration",
        _severity,
        "Password flow missing confirmation signal",
        _description,
    )
)
