"""Same session token appears reused across flows spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("cross_flow_reuse") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Check whether the same token is accepted across unrelated endpoints, steps, or privilege boundaries."


register_spec(
    (
        "session_reuse_detection",
        "broken_authentication",
        _severity,
        "Same session token appears reused across flows",
        _description,
    )
)
