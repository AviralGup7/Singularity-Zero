"""Permissive CORS preflight policy spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if "preflight_allows_authorization_header" in item.get("issues", []) else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Validate the preflight response from a browser context and confirm whether credentialed or sensitive cross-origin writes are possible."


register_spec(
    (
        "cors_preflight_probe",
        "misconfiguration",
        _severity,
        "Permissive CORS preflight policy",
        _description,
    )
)
