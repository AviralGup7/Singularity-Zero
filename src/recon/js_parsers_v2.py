"""AST-aware JS endpoint / route extraction (v2).

The original ``js_parsers`` module relies on a small set of regex
patterns. That works for the simple case of ``axios.get("/users")`` but
misses huge swathes of modern framework code.

This module is a *tokenizer-light* parser: it strips comments and
string literals, walks the remaining token stream to balance braces /
parens, and extracts the arguments of every call expression whose
callee looks like a fetch / axios / request / api wrapper. It also
extracts WebSocket / EventSource URLs, source-map-de-mangled sources,
and htmx-style HTML attribute endpoints.

The output is a set of candidate URLs / paths that the downstream
``js_discovery`` step merges with the legacy regex results.
"""

from __future__ import annotations

# Backward-compatible shim: re-export everything from the modularized package
from src.recon.js_parsers import (
    _strip_strings_and_comments,
    analyze_service_worker,
    analyze_wasm_url,
    discover_and_analyze_manifest,
    extract_api_keys,
    extract_axios_interceptors,
    extract_endpoint_calls,
    extract_endpoints_v2,
    extract_graphql_tagged_literals,
    extract_html_attribute_endpoints,
    extract_jwt_tokens,
    extract_new_request_urls,
    extract_source_map_url,
    extract_sources_content,
    extract_tokens_and_keys,
    extract_websocket_endpoints,
    follow_source_map_chain,
    is_source_map_body,
)

__all__ = [
    "_strip_strings_and_comments",
    "analyze_service_worker",
    "analyze_wasm_url",
    "discover_and_analyze_manifest",
    "extract_api_keys",
    "extract_axios_interceptors",
    "extract_endpoint_calls",
    "extract_endpoints_v2",
    "extract_graphql_tagged_literals",
    "extract_html_attribute_endpoints",
    "extract_jwt_tokens",
    "extract_new_request_urls",
    "extract_source_map_url",
    "extract_sources_content",
    "extract_tokens_and_keys",
    "extract_websocket_endpoints",
    "follow_source_map_chain",
    "is_source_map_body",
]
