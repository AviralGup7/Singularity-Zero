"""GraphQL introspection exposure spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high"


def _description(item: dict[str, Any]) -> str:
    return "Query the exposed schema manually and enumerate high-value object types and mutations."


register_spec(
    (
        "graphql_introspection_exposure_checker",
        "exposure",
        _severity,
        "GraphQL introspection exposure",
        _description,
    )
)
