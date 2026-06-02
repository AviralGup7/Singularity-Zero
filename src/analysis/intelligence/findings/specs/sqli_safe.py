"""SQL error response detected under safe probe spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("probes") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Review the SQL error pattern and confirm whether the parameter is vulnerable to SQL injection. Test with additional safe payloads to verify."


register_spec(
    (
        "sqli_safe_probe",
        "sql_injection",
        _severity,
        "SQL error response detected under safe probe",
        _description,
    )
)
