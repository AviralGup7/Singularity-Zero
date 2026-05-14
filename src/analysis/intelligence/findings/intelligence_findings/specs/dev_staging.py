"""Dev or staging environment detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Compare the non-production host with the main environment for weaker auth, debug toggles, and leaked build metadata."


register_spec(
    (
        "dev_staging_environment_detection",
        "exposure",
        _severity,
        "Dev or staging environment detected",
        _description,
    )
)
