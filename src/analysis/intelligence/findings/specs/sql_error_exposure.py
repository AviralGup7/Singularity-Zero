"""SQL error exposure finding spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return str(item.get("severity") or "medium")


def _description(item: dict[str, Any]) -> str:
    params = ", ".join(item.get("parameters") or [])
    if params:
        return f"Review the SQL error disclosure and verify injection handling for parameter(s): {params}."
    return "Review the SQL error disclosure and confirm database errors are not exposed to clients."


register_spec(
    (
        "sql_error_exposure_detector",
        "sql_injection",
        _severity,
        "SQL error disclosure detected",
        _description,
    )
)
