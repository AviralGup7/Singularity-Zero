"""Backward-compatible shim — re-exports from src.recon.graphql package.

This file exists so that ``from src.recon.graphql_introspection import ...``
continues to work. All new code should import from ``src.recon.graphql`` directly.
"""

from src.recon.graphql import (  # noqa: F401
    DEFAULT_GRAPHQL_PATHS,
    GraphQLEndpoint,
    discover_graphql_endpoints,
    filter_introspection_ok,
    introspect_endpoint_async,
    summarize_endpoints,
)

__all__ = [
    "DEFAULT_GRAPHQL_PATHS",
    "GraphQLEndpoint",
    "discover_graphql_endpoints",
    "filter_introspection_ok",
    "introspect_endpoint_async",
    "summarize_endpoints",
]
