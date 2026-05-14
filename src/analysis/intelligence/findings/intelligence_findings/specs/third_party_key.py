"""Third-party key exposure spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Verify whether the exposed third-party key is intended to be public and what scopes it enables."


register_spec(
    (
        "third_party_key_exposure_checker",
        "exposure",
        _severity,
        "Third-party key exposure",
        _description,
    )
)
