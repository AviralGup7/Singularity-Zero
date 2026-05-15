"""DNS misconfiguration signal spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "low"


def _description(item: dict[str, Any]) -> str:
    return "Review the exposed DNS-related content for weak SPF, missing DMARC hints, or debug leakage."


register_spec(
    (
        "dns_misconfiguration_signal_checker",
        "misconfiguration",
        _severity,
        "DNS misconfiguration signal",
        _description,
    )
)
