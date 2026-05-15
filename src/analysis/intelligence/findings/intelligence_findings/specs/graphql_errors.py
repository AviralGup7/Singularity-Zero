"""Verbose GraphQL error leakage spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Use the leaked field and type names to guide safer follow-up GraphQL testing."


register_spec(
    (
        "graphql_error_leakage_checker",
        "exposure",
        _severity,
        "Verbose GraphQL error leakage",
        _description,
    )
)
