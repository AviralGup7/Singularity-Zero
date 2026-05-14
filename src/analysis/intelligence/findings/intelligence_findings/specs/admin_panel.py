"""Admin panel path discovered spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Review the discovered admin-oriented path for exposed dashboards, setup flows, and auth weaknesses."


register_spec(
    (
        "admin_panel_path_detection",
        "exposure",
        _severity,
        "Admin panel path discovered",
        _description,
    )
)
