"""Verbose error reveals internal field names spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if item.get("inferred_fields") else "low"


def _description(item: dict[str, Any]) -> str:
    return "Use the leaked field names to guide safer follow-up probes on hidden filters, sort keys, or body fields."


register_spec(
    (
        "error_based_inference",
        "exposure",
        _severity,
        "Verbose error reveals internal field names",
        _description,
    )
)
