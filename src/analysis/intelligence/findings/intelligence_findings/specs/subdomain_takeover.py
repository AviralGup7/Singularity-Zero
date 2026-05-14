"""Potential dangling subdomain indicator spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Validate the hostname manually against takeover fingerprints before any claim attempt."


register_spec(
    (
        "subdomain_takeover_indicator_checker",
        "exposure",
        _severity,
        "Potential dangling subdomain indicator",
        _description,
    )
)
