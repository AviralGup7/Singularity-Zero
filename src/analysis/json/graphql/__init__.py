"""GraphQL introspection analysis package.

Provides endpoint detection, schema introspection, query depth abuse testing,
batch query aliasing attacks, and mutation exposure analysis for GraphQL APIs.
"""

from .analyzer import (
    detect_graphql_endpoints,
    run_graphql_analysis,
    test_batch_aliasing,
    test_introspection,
    test_mutation_exposure,
    test_query_depth,
)
from .query_builder import (
    ALIAS_ABUSE_QUERY,
    BATCH_ALIAS_PAYLOADS,
    DEPTH_TEST_QUERIES,
    INTROSPECTION_QUERY,
    MINIMAL_INTROSPECTION_QUERY,
    MUTATION_TEST_QUERIES,
    TYPE_INTROSPECTION_QUERY,
)
from .vulnerability_checker import DANGEROUS_MUTATION_NAMES

__all__ = [
    "detect_graphql_endpoints",
    "test_introspection",
    "test_query_depth",
    "test_batch_aliasing",
    "test_mutation_exposure",
    "run_graphql_analysis",
    "INTROSPECTION_QUERY",
    "MINIMAL_INTROSPECTION_QUERY",
    "TYPE_INTROSPECTION_QUERY",
    "DEPTH_TEST_QUERIES",
    "BATCH_ALIAS_PAYLOADS",
    "ALIAS_ABUSE_QUERY",
    "MUTATION_TEST_QUERIES",
    "DANGEROUS_MUTATION_NAMES",
]
