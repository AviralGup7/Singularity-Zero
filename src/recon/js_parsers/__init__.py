"""JS parsers package - modularized from js_parsers_v2.py and legacy js_parsers.py."""

from __future__ import annotations

from src.recon.js_parsers.ast_extractors import (
    _find_balanced_arg,
    _resolve_call_endpoint,
    _resolve_template_to_pattern,
    _split_args,
    _strip_strings_and_comments,
    extract_endpoint_calls,
)
from src.recon.js_parsers.endpoints import (
    _is_in_scope_url,
    _is_minified_or_node_modules,
    analyze_service_worker,
    analyze_wasm_url,
    discover_and_analyze_manifest,
)
from src.recon.js_parsers.legacy import (
    _AXIOS_FETCH_RE,
    _CONCAT_ROUTE_RE,
    _DYNAMIC_IMPORT_RE,
    _JS_ENDPOINT_RE,
    _SCRIPT_SRC_RE,
    _TEMPLATE_LITERAL_RE,
    _extract_js_ast_endpoints,
    _extract_js_candidate_urls,
    _extract_script_urls_from_html,
    _normalized_scope_roots,
)
from src.recon.js_parsers.parser import (
    _scan_source_contents,
    extract_endpoints_v2,
    follow_source_map_chain,
)

# Re-export all symbols from sub-modules for backward compatibility
from src.recon.js_parsers.regex_extractors import (
    _ALPINE_RE,
    _API_KEY_RE,
    _AXIOS_INTERCEPTOR_RE,
    _BLOCK_COMMENT_RE,
    _FETCH_LIKE_RE,
    _GRAPHQL_GQL_RE,
    _HTMX_RE,
    _JWT_RE,
    _LINE_COMMENT_RE,
    _MINIFIED_EXT_RE,
    _NEW_REQUEST_RE,
    _NODE_MODULES_SEG,
    _SOCKETIO_RE,
    _SOURCE_MAP_RE,
    _STRING_RE,
    _TURBO_RE,
    _WEBSOCKET_RE,
    _candidate_to_absolute_url,
    extract_api_keys,
    extract_axios_interceptors,
    extract_graphql_tagged_literals,
    extract_html_attribute_endpoints,
    extract_jwt_tokens,
    extract_new_request_urls,
    extract_source_map_url,
    extract_sources_content,
    extract_tokens_and_keys,
    extract_websocket_endpoints,
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
