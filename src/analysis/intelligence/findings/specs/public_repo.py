"""Public repository metadata exposure spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    indicator = item.get("indicator", "")
    return "high" if "repo_contents_exposed" in str(indicator) else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Confirm whether repository metadata is readable and stop before downloading unnecessary history."


register_spec(
    (
        "public_repo_exposure_checker",
        "exposure",
        _severity,
        "Public repository metadata exposure",
        _description,
    )
)
