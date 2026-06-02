"""Server-side injection surface detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    signals = item.get("signals", [])
    vuln_types = item.get("vulnerability_types", [])
    return (
        "high"
        if "response_error_hint" in signals
        and any(v in vuln_types for v in ("command_injection", "remote_code_execution"))
        else "medium"
    )


def _description(item: dict[str, Any]) -> str:
    return "Focus on the flagged parameter family and compare backend error handling with controlled, read-only mutation probes."


register_spec(
    (
        "server_side_injection_surface_analyzer",
        "server_side_injection",
        _severity,
        "Server-side injection surface detected",
        _description,
    )
)
