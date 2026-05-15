"""GraphQL introspection and attack surface spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return str(item.get("severity", "medium"))


def _description(item: dict[str, Any]) -> str:
    return "Review the GraphQL introspection findings, depth abuse results, and batch aliasing tests. Disable introspection in production and enforce query depth limits."


register_spec(
    (
        "graphql_introspection_check",
        "graphql_vulnerability",
        _severity,
        "GraphQL introspection and attack surface",
        _description,
    )
)
