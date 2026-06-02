"""Weak rate-limit signaling spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if "missing_rate_limit_headers" in item.get("issues", []) else "low"


def _description(item: dict[str, Any]) -> str:
    return "Check whether high-value API actions lack visible throttling or backoff cues."


register_spec(
    (
        "rate_limit_header_analyzer",
        "misconfiguration",
        _severity,
        "Weak rate-limit signaling",
        _description,
    )
)
