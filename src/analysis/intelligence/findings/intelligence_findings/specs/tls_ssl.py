"""TLS or certificate weakness detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if "certificate_expired" in item.get("issues", []) else "low"


def _description(item: dict[str, Any]) -> str:
    return "Confirm the certificate state, negotiated protocol version, and whether the weak TLS posture is still externally reachable."


register_spec(
    (
        "tls_ssl_misconfiguration_checks",
        "misconfiguration",
        _severity,
        "TLS or certificate weakness detected",
        _description,
    )
)
