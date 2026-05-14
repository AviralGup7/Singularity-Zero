"""Permissive Referrer-Policy spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "low"


def _description(item: dict[str, Any]) -> str:
    return "Confirm whether sensitive path or query data is leaked cross-origin through referrers."


register_spec(
    (
        "referrer_policy_weakness_checker",
        "misconfiguration",
        _severity,
        "Permissive Referrer-Policy",
        _description,
    )
)
