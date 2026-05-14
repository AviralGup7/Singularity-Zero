"""Open index on nonstandard service port spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Open the nonstandard-port index manually and confirm whether files, backups, or service metadata are browseable."


register_spec(
    (
        "nonstandard_service_index_detection",
        "exposure",
        _severity,
        "Open index on nonstandard service port",
        _description,
    )
)
