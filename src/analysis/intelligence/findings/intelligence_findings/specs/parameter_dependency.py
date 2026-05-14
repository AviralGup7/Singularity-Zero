"""Dependent business parameters react together spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Check whether price, quantity, discount, or role parameters can be manipulated independently of the server-side calculation."


register_spec(
    (
        "parameter_dependency_tracker",
        "business_logic",
        _severity,
        "Dependent business parameters react together",
        _description,
    )
)
