"""Potentially cacheable sensitive response spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Confirm whether authenticated or token-bearing responses are missing private or no-store cache directives."


register_spec(
    (
        "cache_control_checker",
        "misconfiguration",
        _severity,
        "Potentially cacheable sensitive response",
        _description,
    )
)
