"""Main orchestrator for JS endpoint extraction."""

from __future__ import annotations

import json
from urllib.parse import urljoin

from src.recon.js_fetcher import _fetch_text_content
from src.recon.js_parsers.ast_extractors import (
    _resolve_call_endpoint,
    _strip_strings_and_comments,
    extract_endpoint_calls,
)
from src.recon.js_parsers.endpoints import (
    _candidate_to_absolute_url,
    _is_in_scope_url,
    _is_minified_or_node_modules,
)
from src.recon.js_parsers.regex_extractors import (
    extract_axios_interceptors,
    extract_graphql_tagged_literals,
    extract_html_attribute_endpoints,
    extract_new_request_urls,
    extract_source_map_url,
    extract_sources_content,
    extract_websocket_endpoints,
    is_source_map_body,
)


def _scan_source_contents(
    contents: list[str],
    base_ref: str,
    scope_roots: set[str],
    provenance: dict[str, str],
    max_depth: int,
) -> tuple[set[str], dict[str, str]]:
    discovered: set[str] = set()
    for source_body in contents:
        if not source_body or not source_body.strip():
            continue
        src_discovered = extract_endpoints_v2(source_body, base_ref, scope_roots)
        discovered.update(src_discovered)
        for ep in src_discovered:
            provenance[ep] = base_ref
    return discovered, provenance


def follow_source_map_chain(
    js_url: str,
    js_body: str,
    base_url: str,
    scope_roots: set[str],
    depth: int = 0,
    provenance: dict[str, str] | None = None,
) -> tuple[set[str], dict[str, str]]:
    """Recursively follow source maps up to 3 hops, building endpoint provenance."""
    if provenance is None:
        provenance = {}
    if depth >= 3:
        return set(), provenance
    discovered: set[str] = set()
    map_url = extract_source_map_url(js_body)
    if not map_url:
        return discovered, provenance
    resolved_map = urljoin(js_url, map_url)
    if _is_minified_or_node_modules(resolved_map):
        return discovered, provenance
    map_body = _fetch_text_content(resolved_map, 8, 250_000)
    if not map_body or not is_source_map_body(map_body):
        return discovered, provenance
    proven = dict(provenance)
    sources = extract_sources_content(map_body)
    if sources:
        src_disc, proven = _scan_source_contents(sources, resolved_map, scope_roots, proven, depth)
        discovered.update(src_disc)
    else:
        body_disc = extract_endpoints_v2(map_body, resolved_map, scope_roots)
        discovered.update(body_disc)
        for ep in body_disc:
            proven[ep] = resolved_map
    from src.recon.js_parsers import _extract_js_candidate_urls

    cand = _extract_js_candidate_urls(map_body, resolved_map, scope_roots)
    discovered.update(cand)
    for ep in cand:
        proven[ep] = resolved_map
    try:
        map_data = json.loads(map_body) or {}
    except json.JSONDecodeError:
        return discovered, proven
    for source_url in map_data.get("sources", []) or []:
        if not isinstance(source_url, str):
            continue
        abs_src = urljoin(resolved_map, source_url)
        if _is_minified_or_node_modules(abs_src):
            continue
        src_body = _fetch_text_content(abs_src, 6, 150_000)
        if not src_body:
            continue
        src_disc = extract_endpoints_v2(src_body, abs_src, scope_roots)
        discovered.update(src_disc)
        for ep in src_disc:
            proven[ep] = abs_src
        next_disc, proven = follow_source_map_chain(
            abs_src, src_body, base_url, scope_roots, depth + 1, proven
        )
        discovered.update(next_disc)
    return discovered, proven


def extract_endpoints_v2(
    content: str,
    base_url: str,
    scope_roots: set[str],
) -> set[str]:
    """Run the v2 (AST-aware + WebSocket + HTML attr) extraction pipeline."""
    discovered: set[str] = set()

    if not content:
        return discovered

    stripped = _strip_strings_and_comments(content)
    for arg_expr in extract_endpoint_calls(stripped):
        resolved = _resolve_call_endpoint(arg_expr, base_url)
        if resolved and _is_in_scope_url(resolved, scope_roots):
            discovered.add(resolved)
    for arg_expr in extract_endpoint_calls(content):
        resolved = _resolve_call_endpoint(arg_expr, base_url)
        if resolved and _is_in_scope_url(resolved, scope_roots):
            discovered.add(resolved)

    for url in extract_websocket_endpoints(content):
        discovered.add(url)

    for value in extract_html_attribute_endpoints(content):
        resolved = _candidate_to_absolute_url(value, base_url)
        if resolved and _is_in_scope_url(resolved, scope_roots):
            discovered.add(resolved)

    for arg_expr in extract_new_request_urls(content):
        resolved = _candidate_to_absolute_url(arg_expr, base_url)
        if resolved and _is_in_scope_url(resolved, scope_roots):
            discovered.add(resolved)

    for url in extract_axios_interceptors(content):
        if not url.startswith(("javascript:", "data:")):
            discovered.add(url)

    for ql in extract_graphql_tagged_literals(content):
        discovered.add(ql)

    return discovered
