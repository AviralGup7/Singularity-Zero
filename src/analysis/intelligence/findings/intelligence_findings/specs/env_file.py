"""Environment or config file exposure spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    indicator = item.get("indicator", "")
    return "high" if "env_file_contents" in str(indicator) else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Validate whether the exposed config contains active credentials, internal hosts, or feature flags."


register_spec(
    (
        "environment_file_exposure_checker",
        "exposure",
        _severity,
        "Environment or config file exposure",
        _description,
    )
)
