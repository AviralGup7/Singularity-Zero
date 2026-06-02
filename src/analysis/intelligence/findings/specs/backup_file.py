"""Backup file exposure hint spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Check whether the backup artifact is directly downloadable and whether it contains source or secrets."


register_spec(
    (
        "backup_file_exposure_checker",
        "exposure",
        _severity,
        "Backup file exposure hint",
        _description,
    )
)
