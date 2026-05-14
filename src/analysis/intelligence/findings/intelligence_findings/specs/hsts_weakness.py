"""Weak HSTS configuration spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "low"


def _description(item: dict[str, Any]) -> str:
    return "Verify the HSTS deployment covers subdomains and uses a long enough max-age."


register_spec(
    (
        "hsts_weakness_checker",
        "misconfiguration",
        _severity,
        "Weak HSTS configuration",
        _description,
    )
)
