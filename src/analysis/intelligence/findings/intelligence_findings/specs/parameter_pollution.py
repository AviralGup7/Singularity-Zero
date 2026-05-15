"""Duplicate parameter pollution indicator spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Replay the endpoint with duplicate parameters and compare which value wins server-side."


register_spec(
    (
        "parameter_pollution_indicator_checker",
        "misconfiguration",
        _severity,
        "Duplicate parameter pollution indicator",
        _description,
    )
)
