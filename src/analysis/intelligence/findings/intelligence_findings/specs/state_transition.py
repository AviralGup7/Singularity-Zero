"""State transition mismatch under parameter change spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("state_mismatch") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Confirm whether changing the step or state parameter lets the flow skip required checks or approvals."


register_spec(
    (
        "state_transition_analyzer",
        "business_logic",
        _severity,
        "State transition mismatch under parameter change",
        _description,
    )
)
