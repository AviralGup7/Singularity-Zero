"""Unsafe HTTP methods exposed spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Verify whether the exposed methods are actually accepted with authenticated or unauthenticated requests."


register_spec(
    (
        "options_method_probe",
        "misconfiguration",
        _severity,
        "Unsafe HTTP methods exposed",
        _description,
    )
)
