"""Suspicious passive CORS policy spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if "wildcard_origin_with_credentials" in item.get("issues", []) else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Confirm whether the endpoint serves sensitive data cross-origin and whether credentials are allowed."


register_spec(
    (
        "cors_misconfig_checker",
        "misconfiguration",
        _severity,
        "Suspicious passive CORS policy",
        _description,
    )
)
