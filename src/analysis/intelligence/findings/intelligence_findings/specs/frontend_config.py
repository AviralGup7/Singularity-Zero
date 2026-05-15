"""Frontend configuration exposure hint spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "low"


def _description(item: dict[str, Any]) -> str:
    return "Mine the exposed frontend config for hidden APIs, GraphQL endpoints, and secondary hosts before the next run."


register_spec(
    (
        "frontend_config_exposure_checker",
        "exposure",
        _severity,
        "Frontend configuration exposure hint",
        _description,
    )
)
