"""Endpoint behavior changes after controlled role change spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("accessible_after_role_change") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Review the read-only role or scope parameter change and verify whether it exposes data that should remain outside the caller's authorization boundary."


register_spec(
    (
        "privilege_escalation_detector",
        "access_control",
        _severity,
        "Endpoint behavior changes after controlled role change",
        _description,
    )
)
