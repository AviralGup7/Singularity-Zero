"""Cloud storage exposure hint spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    indicator = item.get("indicator", "")
    return "high" if "bucket_listing_or_error" in str(indicator) else "medium"


def _description(item: dict[str, Any]) -> str:
    return (
        "Check whether bucket or object listing is public and whether sensitive paths are readable."
    )


register_spec(
    (
        "cloud_storage_exposure_checker",
        "exposure",
        _severity,
        "Cloud storage exposure hint",
        _description,
    )
)
