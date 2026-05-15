"""Inconsistent JSON response structure detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("severity") == "high" else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Review the drifting fields to confirm whether conditional field exposure or role-based response shaping is occurring."


register_spec(
    (
        "response_structure_validator",
        "exposure",
        _severity,
        "Inconsistent JSON response structure detected",
        _description,
    )
)
