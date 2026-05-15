"""Accessible log or debug output spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Review the log safely for tokens, stack traces, internal paths, and usernames."


register_spec(
    (
        "log_file_exposure_checker",
        "exposure",
        _severity,
        "Accessible log or debug output",
        _description,
    )
)
