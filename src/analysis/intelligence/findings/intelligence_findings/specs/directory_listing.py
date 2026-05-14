"""Directory listing pattern detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Open the path manually and confirm whether file names, backups, or uploaded objects are browsable."


register_spec(
    (
        "directory_listing_checker",
        "exposure",
        _severity,
        "Directory listing pattern detected",
        _description,
    )
)
