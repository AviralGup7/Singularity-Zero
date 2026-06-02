"""Later workflow step appears directly reachable spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("step_skip_possible") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Walk the flow from a clean session and confirm whether the later step can be loaded without completing the earlier prerequisite state."


register_spec(
    (
        "multi_step_flow_breaking_probe",
        "business_logic",
        _severity,
        "Later workflow step appears directly reachable",
        _description,
    )
)
