"""Reflected input sink detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    xss_signals = item.get("xss_signals", [])
    return (
        "high"
        if "script_context" in xss_signals or "attribute_context" in xss_signals
        else "medium"
    )


def _description(item: dict[str, Any]) -> str:
    return "Replay the harmless marker in a safe browser test flow and confirm whether the reflected value reaches an executable HTML or script context."


register_spec(
    (
        "reflected_xss_probe",
        "xss",
        _severity,
        "Reflected input sink detected",
        _description,
    )
)
