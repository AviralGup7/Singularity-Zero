"""TRACE method accepted spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Confirm whether TRACE is consistently enabled and whether any sensitive headers are reflected in the response path."


register_spec(
    (
        "trace_method_probe",
        "misconfiguration",
        _severity,
        "TRACE method accepted",
        _description,
    )
)
