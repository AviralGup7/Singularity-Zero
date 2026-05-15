"""Locale or debug toggle parameter spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "low"


def _description(item: dict[str, Any]) -> str:
    return "Test whether the toggle affects verbosity, rendering, or hidden code paths."


register_spec(
    (
        "locale_debug_toggle_checker",
        "misconfiguration",
        _severity,
        "Locale or debug toggle parameter",
        _description,
    )
)
