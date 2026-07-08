"""API spec discovery package - re-exports for backward compatibility."""

from __future__ import annotations

from src.recon.api_specs.discovery import (
    discover_api_specs,
    extract_auth_headers_from_js_parsers,
)
from src.recon.api_specs.grpc import (
    DEFAULT_GRPC_PATHS,
    DEFAULT_GRPC_WEB_PATHS,
    DEFAULT_PROTO_PATHS,
    grpcurl_describe_service,
    grpcurl_list_services,
)
from src.recon.api_specs.openapi import (
    DEFAULT_ASYNCAPI_PATHS,
    DEFAULT_AVRO_PATHS,
    DEFAULT_GRAPHQL_SDL_PATHS,
    DEFAULT_SERVER_VARIABLES,
    DEFAULT_SPEC_PATHS,
    DEFAULT_THRIFT_PATHS,
    SpecEndpoint,
    extract_operation_summaries,
    merge_openapi_specs,
)

__all__ = [
    "DEFAULT_ASYNCAPI_PATHS",
    "DEFAULT_AVRO_PATHS",
    "DEFAULT_GRAPHQL_SDL_PATHS",
    "DEFAULT_GRPC_PATHS",
    "DEFAULT_GRPC_WEB_PATHS",
    "DEFAULT_PROTO_PATHS",
    "DEFAULT_SPEC_PATHS",
    "DEFAULT_SERVER_VARIABLES",
    "DEFAULT_THRIFT_PATHS",
    "SpecEndpoint",
    "discover_api_specs",
    "extract_auth_headers_from_js_parsers",
    "extract_operation_summaries",
    "grpcurl_describe_service",
    "grpcurl_list_services",
    "merge_openapi_specs",
]
