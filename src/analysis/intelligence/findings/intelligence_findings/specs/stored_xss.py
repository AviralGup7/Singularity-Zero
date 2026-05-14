"""Stored XSS signal in response field spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    xss_signals = item.get("xss_signals", [])
    return "high" if "script_tag" in xss_signals or "event_handler" in xss_signals else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Confirm whether the dangerous markup is user-controlled and rendered in a browser-facing view without sanitization."


register_spec(
    (
        "stored_xss_signal_detector",
        "xss",
        _severity,
        "Stored XSS signal in response field",
        _description,
    )
)
