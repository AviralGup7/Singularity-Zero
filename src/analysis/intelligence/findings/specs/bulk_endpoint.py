"""Bulk or collection-style endpoint detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Replay the collection endpoint with pagination, export, and filter changes to confirm whether large datasets are exposed."


register_spec(
    (
        "bulk_endpoint_detector",
        "exposure",
        _severity,
        "Bulk or collection-style endpoint detected",
        _description,
    )
)
