"""Unexpected HEAD behavior on endpoint spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "low"


def _description(item: dict[str, Any]) -> str:
    return "Compare HEAD and GET manually to see whether security controls or response metadata diverge in a meaningful way."


register_spec(
    (
        "head_method_probe",
        "misconfiguration",
        _severity,
        "Unexpected HEAD behavior on endpoint",
        _description,
    )
)
