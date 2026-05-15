"""GraphQL surface exposed spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("introspection_result", {}).get("schema_exposed") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Review the GraphQL schema exposure, batch query acceptance, and mutation surface. Confirm whether introspection should be disabled in production."


register_spec(
    (
        "graphql_active_probe",
        "graphql",
        _severity,
        "GraphQL surface exposed",
        _description,
    )
)
