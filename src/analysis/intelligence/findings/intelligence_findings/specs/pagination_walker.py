"""Pagination mutation changes data window spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if item.get("mutated_status") == item.get("original_status") else "low"


def _description(item: dict[str, Any]) -> str:
    return "Compare nearby pages and offsets in a controlled way to confirm whether the data window expands unexpectedly."


register_spec(
    (
        "pagination_walker",
        "exposure",
        _severity,
        "Pagination mutation changes data window",
        _description,
    )
)
