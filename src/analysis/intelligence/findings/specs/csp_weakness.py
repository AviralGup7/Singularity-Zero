"""Weak Content-Security-Policy spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if len(item.get("issues", [])) < 3 else "high"


def _description(item: dict[str, Any]) -> str:
    return "Tighten unsafe directives and verify whether exploitable script injection sinks exist."


register_spec(
    (
        "csp_weakness_analyzer",
        "misconfiguration",
        _severity,
        "Weak Content-Security-Policy",
        _description,
    )
)
