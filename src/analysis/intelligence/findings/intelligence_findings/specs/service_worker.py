"""Service worker scope or caching weakness spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Review the service worker scope and cached path coverage for auth or admin content."


register_spec(
    (
        "service_worker_misconfiguration_checker",
        "misconfiguration",
        _severity,
        "Service worker scope or caching weakness",
        _description,
    )
)
