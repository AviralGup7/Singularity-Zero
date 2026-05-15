"""Missing rate-limit signals on data endpoint spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Confirm from normal-volume reads whether the endpoint exposes throttling, quota, or backoff guidance in a consistent way."


register_spec(
    (
        "rate_limit_signal_analyzer",
        "misconfiguration",
        _severity,
        "Missing rate-limit signals on data endpoint",
        _description,
    )
)
