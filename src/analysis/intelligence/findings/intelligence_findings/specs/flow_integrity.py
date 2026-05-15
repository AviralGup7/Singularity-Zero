"""Flow order inconsistency detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if item.get("step_skipping_possible") else "low"


def _description(item: dict[str, Any]) -> str:
    return "Walk the flow manually and confirm whether later steps can be reached without completing earlier ones."


register_spec(
    (
        "flow_integrity_checker",
        "business_logic",
        _severity,
        "Flow order inconsistency detected",
        _description,
    )
)
