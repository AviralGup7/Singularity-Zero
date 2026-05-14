"""Exposed service interface detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Review whether the detected service should be internet-reachable and whether auth, IP allowlisting, and setup state are enforced."


register_spec(
    (
        "exposed_service_detection",
        "exposure",
        _severity,
        "Exposed service interface detected",
        _description,
    )
)
