"""GraphQL and API spec exposure checkers.

Contains checkers for GraphQL introspection, error leakage, OpenAPI/Swagger
spec exposure, and gRPC reflection exposure.
Extracted from checks/exposure/_impl.py for better separation of concerns.
"""

from typing import Any

from src.analysis.passive.extended_shared import (
    GRAPHQL_ERROR_RE,
    GRAPHQL_INTROSPECTION_RE,
    OPENAPI_RE,
    scan_responses,
    scan_urls_and_responses,
)


def graphql_introspection_exposure_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Check for GraphQL introspection endpoint exposure."""
    return scan_responses(
        responses,
        response_matcher=lambda r: bool(
            (
                "/graphql" in str(r.get("url", "")).lower()
                or "graphql" in (r.get("body_text") or "").lower()
            )
            and GRAPHQL_INTROSPECTION_RE.search((r.get("body_text") or "")[:12000])
        ),
        response_indicator="graphql_introspection_enabled",
        limit=60,
    )


def graphql_error_leakage_checker(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Check for verbose GraphQL error leakage."""
    return scan_responses(
        responses,
        response_matcher=lambda r: bool(
            (
                "/graphql" in str(r.get("url", "")).lower()
                or "graphql" in (r.get("body_text") or "").lower()
            )
            and GRAPHQL_ERROR_RE.search((r.get("body_text") or "")[:12000])
        ),
        response_indicator="verbose_graphql_errors",
        limit=60,
    )


def openapi_swagger_spec_checker(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Check for OpenAPI/Swagger spec exposure."""
    debug_paths = (
        "/swagger",
        "/swagger.json",
        "/swagger-ui",
        "/swagger-ui.html",
        "/swagger-ui/",
        "/openapi",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api-docs",
        "/docs",
        "/redoc",
        "/redoc.html",
        "/graphql-playground",
        "/graphiql",
    )
    return scan_urls_and_responses(
        urls,
        responses,
        url_matcher=lambda url: any(token in url.lower() for token in debug_paths),
        response_matcher=lambda r: bool(OPENAPI_RE.search((r.get("body_text") or "")[:12000])),
        url_indicator="openapi_path_hint",
        response_indicator="openapi_schema_exposed",
        limit=80,
    )


def grpc_reflection_exposure_checker(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Check for gRPC reflection endpoint exposure."""
    grpc_paths = (
        "/grpc.reflection",
        "/grpc.health",
        "/serverreflectioninfo",
        "/grpc.reflection.v1alpha",
        "/grpc.reflection.v1",
        "/grpc.health.v1",
        "/grpc.health.v1.Health",
        "/grpc.health.v1.Health/Check",
        "/debug/grpc",
        "/grpc/debug",
    )
    grpc_reflection_patterns = (
        "grpc.reflection.v1alpha.serverreflection",
        "grpc.reflection.v1.serverreflection",
        "grpc.health.v1",
        "grpc.health.v1.Health",
        "grpc.health.v1.HealthCheckResponse",
    )
    return scan_urls_and_responses(
        urls,
        responses,
        url_matcher=lambda url: any(token in url.lower() for token in grpc_paths),
        response_matcher=lambda r: any(
            pattern in (r.get("body_text") or "").lower()[:8000]
            for pattern in grpc_reflection_patterns
        ),
        url_indicator="grpc_reflection_path_hint",
        response_indicator="grpc_reflection_response",
        limit=40,
    )
