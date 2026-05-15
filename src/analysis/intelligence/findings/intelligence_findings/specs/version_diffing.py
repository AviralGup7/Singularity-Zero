"""Behavior difference across API versions spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if item.get("body_similarity", 1.0) < 0.8 else "low"


def _description(item: dict[str, Any]) -> str:
    return (
        "Compare auth checks, field exposure, and error handling between the observed API versions."
    )


register_spec(
    (
        "version_diffing",
        "exposure",
        _severity,
        "Behavior difference across API versions",
        _description,
    )
)
