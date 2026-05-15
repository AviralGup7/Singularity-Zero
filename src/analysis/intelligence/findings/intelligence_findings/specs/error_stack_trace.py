"""Backend stack trace or verbose error spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Capture the leaked stack information and map the framework, package, and code path details."


register_spec(
    (
        "error_stack_trace_detector",
        "exposure",
        _severity,
        "Backend stack trace or verbose error",
        _description,
    )
)
