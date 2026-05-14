"""Payment provider integration reference detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "low"


def _description(item: dict[str, Any]) -> str:
    return "Correlate the provider markers with checkout, invoice, refund, or webhook routes before deeper review."


register_spec(
    (
        "payment_provider_detection",
        "exposure",
        _severity,
        "Payment provider integration reference detected",
        _description,
    )
)
