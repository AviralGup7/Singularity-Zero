"""Reflected Origin in active CORS probe spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("allow_credentials") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Replay the Origin probe manually and confirm whether credentialed cross-origin reads are possible."


register_spec(
    (
        "origin_reflection_probe",
        "misconfiguration",
        _severity,
        "Reflected Origin in active CORS probe",
        _description,
    )
)
