"""Risky HTTP methods exposed in headers spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Verify whether the advertised methods are actually accepted and meaningful on the endpoint."


register_spec(
    (
        "http_method_exposure_checker",
        "misconfiguration",
        _severity,
        "Risky HTTP methods exposed in headers",
        _description,
    )
)
