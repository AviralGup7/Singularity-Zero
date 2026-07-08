"""Regex constants and regex-based extraction functions."""

from __future__ import annotations

import json
import re

from src.recon.url_validation import is_safe_url

# Regex constants
_STRING_RE = re.compile(
    r"""
    (?:
        '(?:\\.|[^'\\])*'      # single-quoted string
        |
        "(?:\\.|[^"\\])*"      # double-quoted string
        |
        `(?:\\.|[^`\\])*`      # backtick-quoted template literal
    )
    """,
    re.VERBOSE | re.DOTALL,
)

_BLOCK_COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/")
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")

_HTMX_RE = re.compile(
    r'\bhx-(?:get|post|put|patch|delete|connect|target|include|vals|boost|ws|ws-connect|sse)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_ALPINE_RE = re.compile(
    r'(?:x-on:|@)([a-zA-Z][\w-]*)\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)

_TURBO_RE = re.compile(
    r'data-turbo-(?:action|method|frame|src|confirm)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

_WEBSOCKET_RE = re.compile(
    r"""(?:new\s+(?:WebSocket|EventSource|SSE)\s*\(\s*['"`]|io\s*\(\s*['"`]|socket\s*\(\s*['"`])(wss?://[^'"`\s]+)""",
    re.IGNORECASE,
)

_SOCKETIO_RE = re.compile(
    r"\bio\([\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

_FETCH_LIKE_RE = re.compile(
    r"""
    \b(?P<callee>
        (?:[A-Za-z_$][\w$]*\s*\.\s*)*  # optional chain prefix
        (?P<name>
            fetch
            | axios(?:\.[a-z]+)?
            | http\.(?:get|post|put|patch|delete|request)
            | https\.(?:get|post|put|patch|delete|request)
            | request
            | api\.(?:get|post|put|patch|delete|request|fetch)
            | client\.(?:get|post|put|patch|delete|request|fetch)
        )
    )
    \s*\(
    """,
    re.IGNORECASE | re.VERBOSE,
)

_GRAPHQL_GQL_RE = re.compile(
    r"\b(?:gql|graphql)\s*`([^`]*)`",
    re.IGNORECASE,
)

_JWT_RE = re.compile(
    r"\b(?:Bearer|bearer)\s+([A-Za-z0-9_\-\.]+)",
)

_API_KEY_RE = re.compile(
    r"""(?i)\b(?:
        api_key|apikey|api-key|x-api-key|x-api_secret|authorization
    )\s*[:=]\s*["']([^"']{8,})["']""",
    re.VERBOSE,
)

_NEW_REQUEST_RE = re.compile(
    r"""\bnew\s+Request\s*\(\s*(['"`])([^'"`]+)\1""",
    re.IGNORECASE,
)

_AXIOS_INTERCEPTOR_RE = re.compile(
    r"""\baxios\.interceptors\.request\.use\s*\(\s*[^,]+,\s*[^)]*\)""",
    re.IGNORECASE | re.DOTALL,
)

_SOURCE_MAP_RE = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*([^\s'\"\)]+)",
    re.IGNORECASE,
)

_NODE_MODULES_SEG = re.compile(r"(?:^|/)node_modules/", re.IGNORECASE)
_MINIFIED_EXT_RE = re.compile(r"\.(min|chunk|bundle)\.(js|css|mjs)$", re.IGNORECASE)


def _candidate_to_absolute_url(candidate: str, base_url: str) -> str | None:
    """Convert a URL candidate to an absolute URL, filtering unsafe schemes."""
    from urllib.parse import urljoin, urlparse

    cleaned = candidate.strip().strip(chr(34) + chr(39))
    if not cleaned:
        return None
    lowered = cleaned.lower()
    if lowered.startswith(("javascript:", "data:", "mailto:", "#")):
        return None
    if "{" in cleaned or "}" in cleaned:
        return None
    if cleaned.startswith("//"):
        resolved = f"https:{cleaned}"
    elif cleaned.startswith(("http://", "https://")):
        resolved = cleaned
    else:
        resolved = urljoin(base_url, cleaned)
    parsed = urlparse(resolved)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return resolved


def extract_html_attribute_endpoints(html: str) -> set[str]:
    """Extract endpoint-shaped strings from htmx / Alpine / Turbo attributes."""
    candidates: set[str] = set()
    for regex in (_HTMX_RE, _ALPINE_RE, _TURBO_RE):
        for match in regex.finditer(html or ""):
            value = match.group(1) if regex is _ALPINE_RE else match.group(1)
            if value and "/" in value and not value.strip().startswith("javascript:"):
                candidates.add(value.strip())
    return candidates


def extract_websocket_endpoints(content: str) -> set[str]:
    """Extract WebSocket / EventSource / socket.io URLs from JS."""
    candidates: set[str] = set()
    for match in _WEBSOCKET_RE.finditer(content or ""):
        url = match.group(1)
        if url and is_safe_url(url.replace("wss://", "https://").replace("ws://", "http://")):
            candidates.add(url)
    for match in _SOCKETIO_RE.finditer(content or ""):
        url = match.group(1)
        if url and is_safe_url(url.replace("wss://", "https://").replace("ws://", "http://")):
            candidates.add(url)
    return candidates


def extract_graphql_tagged_literals(content: str) -> set[str]:
    candidates: set[str] = set()
    for match in _GRAPHQL_GQL_RE.finditer(content or ""):
        inner = match.group(1)
        if inner and "{" in inner:
            candidates.add(inner.strip())
    return candidates


def extract_jwt_tokens(content: str) -> list[dict[str, str]]:
    tokens: list[dict[str, str]] = []
    for match in _JWT_RE.finditer(content or ""):
        val = match.group(1)
        if val and len(val) > 10:
            tokens.append({"type": "JWT/Bearer", "value": val[:12] + "***"})
    return tokens


def extract_api_keys(content: str) -> list[dict[str, str]]:
    keys: list[dict[str, str]] = []
    for match in _API_KEY_RE.finditer(content or ""):
        val = match.group(1)
        if val and len(val) >= 8:
            keys.append({"type": "API Key", "value": val[:8] + "***"})
    return keys


def extract_new_request_urls(content: str) -> set[str]:
    candidates: set[str] = set()
    for match in _NEW_REQUEST_RE.finditer(content or ""):
        url = match.group(2)
        if url:
            candidates.add(url.strip())
    return candidates


def extract_axios_interceptors(content: str) -> set[str]:
    candidates: set[str] = set()
    for match in _AXIOS_INTERCEPTOR_RE.finditer(content or ""):
        snippet = match.group(0)
        url_matches = re.findall(r"""['"`]([^'"`]*\/[^'"`]*)['"`]""", snippet)
        for url in url_matches:
            if url and not url.startswith(("javascript:", "data:")):
                candidates.add(url.strip())
    return candidates


def extract_tokens_and_keys(content: str) -> list[dict[str, str]]:
    secrets: list[dict[str, str]] = []
    secrets.extend(extract_jwt_tokens(content))
    secrets.extend(extract_api_keys(content))
    return secrets


def extract_source_map_url(js_body: str) -> str | None:
    """Return the URL declared in a ``sourceMappingURL`` comment, or None."""
    match = _SOURCE_MAP_RE.search(js_body or "")
    if not match:
        return None
    return match.group(1).strip()


def extract_sources_content(map_body: str) -> list[str]:
    """Pull the ``sourcesContent`` entries out of a parsed source map."""
    if not map_body:
        return []
    try:
        data = json.loads(map_body)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    contents = data.get("sourcesContent")
    if not isinstance(contents, list):
        return []
    return [c for c in contents if isinstance(c, str) and c]


def is_source_map_body(body: str) -> bool:
    """Return True if *body* parses as a source map JSON document."""
    if not body:
        return False
    head = body.lstrip()[:128]
    if not (head.startswith("{") or head.startswith("//{")):
        return False
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return False
    return isinstance(data, dict) and ("mappings" in data or "sources" in data)
