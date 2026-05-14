"""Multiple API versions exposed spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "low"


def _description(item: dict[str, Any]) -> str:
    return "Compare the exposed API versions for deprecated or less protected routes."


register_spec(
    (
        "api_version_disclosure_checker",
        "exposure",
        _severity,
        "Multiple API versions exposed",
        _description,
    )
)
