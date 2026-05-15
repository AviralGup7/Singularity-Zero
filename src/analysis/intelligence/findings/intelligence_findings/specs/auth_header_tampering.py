"""Auth header variation changes enforcement behavior spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("auth_bypass_variant") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Retry the same endpoint from a clean client with the observed stripped or alternate auth header mode and compare whether access, redirects, or body shape remain intact."


register_spec(
    (
        "auth_header_tampering_variations",
        "authentication_bypass",
        _severity,
        "Auth header variation changes enforcement behavior",
        _description,
    )
)
