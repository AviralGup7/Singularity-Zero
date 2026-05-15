"""Debug or diagnostic artifact hint spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Review the debug-oriented path or response for admin metadata, schema docs, env exposure, or actuator endpoints."


register_spec(
    (
        "debug_artifact_checker",
        "exposure",
        _severity,
        "Debug or diagnostic artifact hint",
        _description,
    )
)
