"""HTTP method override headers change endpoint behavior spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("method_override_detected") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Verify whether the endpoint accepts X-HTTP-Method-Override or similar headers to change the effective HTTP method, potentially bypassing method-level access controls."


register_spec(
    (
        "http_method_override_probe",
        "authentication_bypass",
        _severity,
        "HTTP method override headers change endpoint behavior",
        _description,
    )
)
