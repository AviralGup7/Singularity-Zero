"""Mixed authentication enforcement across endpoints spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Compare the protected and unexpectedly accessible endpoints on the same host to confirm whether auth checks are applied consistently."


register_spec(
    (
        "multi_endpoint_auth_consistency_check",
        "authentication_bypass",
        _severity,
        "Mixed authentication enforcement across endpoints",
        _description,
    )
)
