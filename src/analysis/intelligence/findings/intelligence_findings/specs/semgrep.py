"""Spec registration for Semgrep findings."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    # Expect the pipeline finding to have a normalized severity string
    return str(item.get("severity", "info")).lower()


def _description(item: dict[str, Any]) -> str:
    return "Review the Semgrep finding and triage the static analysis issue in context."


register_spec(
    (
        "semgrep",
        "sast",
        _severity,
        "Static analysis finding (Semgrep)",
        _description,
    )
)
