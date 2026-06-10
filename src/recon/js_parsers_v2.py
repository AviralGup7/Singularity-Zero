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

import json
import logging
import re
import string
from urllib.parse import urljoin, urlparse

import requests

from src.recon.js_fetcher import _fetch_text_content
from src.recon.url_validation import is_safe_url




def _is_in_scope_url(url: str, scope_roots: set[str]) -> bool:
    """Check if URL hostname matches any scope root or subdomain thereof."""
    if not scope_roots:
        return True
    hostname = (urlparse(url).hostname or "").strip().lower()
    if not hostname:
        return False
    return any(hostname == root or hostname.endswith(f".{root}") for root in scope_roots)


def _candidate_to_absolute_url(candidate: str, base_url: str) -> str | None:
    """Convert a URL candidate to an absolute URL, filtering unsafe schemes."""
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

logger = logging.getLogger(__name__)





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


def _strip_strings_and_comments(content: str) -> str:
    """Replace string literals and comments with placeholders of equal length.

    This lets us match balanced delimiters (parens, brackets) without
    tripping over ``// in a string`` or ``/* in a regex */``. The
    placeholder is spaces so byte offsets stay aligned with the
    original.
    """
    def _blank(match: re.Match[str]) -> str:
        return " " * len(match.group(0))

    content = _BLOCK_COMMENT_RE.sub(_blank, content)
    content = _LINE_COMMENT_RE.sub(_blank, content)
    content = _STRING_RE.sub(_blank, content)
    return content





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


def extract_html_attribute_endpoints(html: str) -> set[str]:
    """Extract endpoint-shaped strings from htmx / Alpine / Turbo attributes.

    The function is permissive: it returns every value it finds, leaving
    the in-scope filter to the caller. This is a feature — Alpine's
    ``@click="window.location='/admin'"`` is exactly the kind of bug
    bounty finding we want to surface.
    """
    candidates: set[str] = set()
    for regex in (_HTMX_RE, _ALPINE_RE, _TURBO_RE):
        for match in regex.finditer(html or ""):
            value = match.group(1) if regex is _ALPINE_RE else match.group(1)
            if value and "/" in value and not value.strip().startswith("javascript:"):
                candidates.add(value.strip())
    return candidates





_WEBSOCKET_RE = re.compile(
    r"""(?:new\s+(?:WebSocket|EventSource|SSE)\s*\(\s*['"`]|io\s*\(\s*['"`]|socket\s*\(\s*['"`])(wss?://[^'"`\s]+)""",
    re.IGNORECASE,
)


_SOCKETIO_RE = re.compile(
    r"\bio\([\"']([^\"']+)[\"']",
    re.IGNORECASE,
)


def extract_websocket_endpoints(content: str) -> set[str]:
    """Extract WebSocket / EventSource / socket.io URLs from JS.

    The previous pipeline dropped non-http schemes. WebSockets are a
    significant attack surface (auth bypass, message injection, rate
    limit bypass) and EventSource streams are commonly used for
    server-sent notifications.
    """
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





def _find_balanced_arg(content: str, start: int) -> tuple[str, int] | None:
    """Return the substring of the first balanced paren expression starting at *start*.

    The function assumes ``content[start] == '('`` and walks forward
    balancing nested parens. Strings, comments, and template literals
    are honoured (their internal parens are not counted).

    Returns (substring, end_index) or None when unbalanced.
    """
    if start >= len(content) or content[start] != "(":
        return None
    depth = 0
    i = start
    in_str = False
    str_ch = ""
    in_template = False
    template_depth = 0
    while i < len(content):
        ch = content[i]
        if in_str:
            if ch == "\\" and i + 1 < len(content):
                i += 2
                continue
            if ch == str_ch:
                in_str = False
            i += 1
            continue
        if in_template:
            if ch == "\\" and i + 1 < len(content):
                i += 2
                continue
            if ch == "`":
                in_template = False
                i += 1
                continue
            if ch == "$" and i + 1 < len(content) and content[i + 1] == "{":
                template_depth += 1
                i += 2
                continue
            if ch == "}" and template_depth > 0:
                template_depth -= 1
                i += 1
                continue
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = True
            str_ch = ch
            i += 1
            continue
        if ch == "`":
            in_template = True
            i += 1
            continue
        if ch == "/" and i + 1 < len(content) and content[i + 1] == "/":
            nl = content.find("\n", i)
            i = len(content) if nl == -1 else nl + 1
            continue
        if ch == "/" and i + 1 < len(content) and content[i + 1] == "*":
            end = content.find("*/", i + 2)
            i = len(content) if end == -1 else end + 2
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return content[start + 1 : i], i
        i += 1
    return None


def _split_args(args_blob: str) -> list[str]:
    """Split the top-level comma-separated arguments inside a balanced call.

    Honours balanced parens, brackets, and braces so an object literal
    as the second argument does not get sliced.
    """
    if not args_blob:
        return []
    args: list[str] = []
    depth_paren = depth_bracket = depth_brace = 0
    in_str = False
    str_ch = ""
    current: list[str] = []
    for ch in args_blob:
        if in_str:
            current.append(ch)
            if ch == "\\" and current:
                continue
            if ch == str_ch:
                in_str = False
            continue
        if ch in ('"', "'"):
            in_str = True
            str_ch = ch
            current.append(ch)
            continue
        if ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren -= 1
        elif ch == "[":
            depth_bracket += 1
        elif ch == "]":
            depth_bracket -= 1
        elif ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace -= 1
        if (
            ch == ","
            and depth_paren == 0
            and depth_bracket == 0
            and depth_brace == 0
        ):
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    if current:
        args.append("".join(current).strip())
    return args


def extract_endpoint_calls(content: str) -> list[str]:
    """AST-aware extraction of fetch-like call argument strings.

    Returns the raw first-argument expressions of every match. The
    caller is responsible for resolving templates and validating scope.
    """
    candidates: list[str] = []
    for match in _FETCH_LIKE_RE.finditer(content or ""):
        paren_start = match.end() - 1
        balanced = _find_balanced_arg(content, paren_start)
        if not balanced:
            continue
        args_blob, _ = balanced
        if not args_blob:
            continue
        first_args = _split_args(args_blob)
        if not first_args:
            continue
        first = first_args[0]
        if first:
            candidates.append(first)
    return candidates





_SOURCE_MAP_RE = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*([^\s'\"\)]+)",
    re.IGNORECASE,
)


def extract_source_map_url(js_body: str) -> str | None:
    """Return the URL declared in a ``sourceMappingURL`` comment, or None."""
    match = _SOURCE_MAP_RE.search(js_body or "")
    if not match:
        return None
    return match.group(1).strip()


def extract_sources_content(map_body: str) -> list[str]:
    """Pull the ``sourcesContent`` entries out of a parsed source map.

    The function decodes the JSON map and returns the list of
    ``sourcesContent`` strings, which webpack-style maps populate with
    the original (un-minified) source. These bodies are the
    highest-signal target for endpoint extraction: a minified bundle
    is near-impossible to read, but the original source has readable
    endpoint strings.

    Returns an empty list if the body is not a valid source map.
    """
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




_NODE_MODULES_SEG = re.compile(r"(?:^|/)node_modules/", re.IGNORECASE)
_MINIFIED_EXT_RE = re.compile(r"\.(min|chunk|bundle)\.(js|css|mjs)$", re.IGNORECASE)


def _is_minified_or_node_modules(url: str) -> bool:
    if _NODE_MODULES_SEG.search(url or ""):
        return True
    if _MINIFIED_EXT_RE.search(url or ""):
        return True
    return False


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
        next_disc, proven = follow_source_map_chain(abs_src, src_body, base_url, scope_roots, depth + 1, proven)
        discovered.update(next_disc)
    return discovered, proven


def analyze_wasm_url(
    wasm_url: str,
    base_url: str,
    scope_roots: set[str],
    max_bytes: int = 50000,
) -> tuple[set[str], list[str]]:
    wasm_discovered: set[str] = set()
    wasm_strings: list[str] = []
    if not (wasm_url or "").endswith(".wasm"):
        return wasm_discovered, wasm_strings
    hostname = (urlparse(wasm_url).hostname or "").lower()
    if scope_roots and not any(hostname == r or hostname.endswith("." + r) for r in scope_roots):
        return wasm_discovered, wasm_strings
    try:
        resp = requests.get(
            wasm_url,
            timeout=8,
            allow_redirects=False,
            headers={"User-Agent": "target-specific-pipeline/2.0"},
        )
        if resp.status_code >= 400:
            return wasm_discovered, wasm_strings
        data = resp.content[:max_bytes]
    except requests.RequestException:
        return wasm_discovered, wasm_strings
    ascii_chars = set(string.printable)
    current: list[str] = []
    for byte in data:
        ch = chr(byte)
        if ch in ascii_chars and ch != "\x00":
            current.append(ch)
        else:
            if len(current) >= 6:
                s = "".join(current)
                wasm_strings.append(s)
                for url in re.findall(r"(https?://[^\s\"'<>]+)", s):
                    wasm_discovered.add(url)
                for path in re.findall(r"(/[A-Za-z0-9_/\-]{3,}(?:\?[^\s\"'<>]*)?)", s):
                    wasm_discovered.add(urljoin(base_url, path))
            current = []
    return wasm_discovered, wasm_strings


def analyze_service_worker(
    sw_url: str,
    base_url: str,
    scope_roots: set[str],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "sw_url": sw_url,
        "cache_names": [],
        "fetch_routes": [],
        "sync_endpoints": [],
        "push_endpoints": [],
        "wasm_references": [],
    }
    body = _fetch_text_content(sw_url, 8, 250_000)
    if not body:
        return result
    for match in re.finditer(r'["\']([^"\']+\.wasm)["\']', body):
        wasm_url = match.group(1)
        resolved = urljoin(sw_url, wasm_url)
        if is_safe_url(resolved):
            result["wasm_references"].append(resolved)
    for name_match in re.finditer(r'cacheName\s*[:=]\s*["\']([^"\']+)["\']', body):
        result["cache_names"].append(name_match.group(1))
    route_patterns = re.findall(
        r"""(?:event\.request|fetch\(\s*)(['"`])([^'"`]+)\1""",
        body,
    )
    for _, route in route_patterns:
        if route and not route.startswith(("javascript:", "data:")):
            result["fetch_routes"].append(route)
    for push_match in re.finditer(r'push\.subscribe\s*\(\s*["\']([^"\']+)["\']', body):
        result["push_endpoints"].append(push_match.group(1))
    for sync_match in re.finditer(r'sync\.register\s*\(\s*["\']([^"\']+)["\']', body):
        result["sync_endpoints"].append(sync_match.group(1))
    return result


def discover_and_analyze_manifest(
    base_url: str,
    scope_roots: set[str],
    html_body: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "manifest_url": None,
        "discovered": False,
        "start_url": None,
        "scope": None,
        "related_applications": [],
        "shortcuts": [],
        "external_start_url": False,
        "warnings": [],
        "raw": None,
    }
    candidates: list[str] = []
    if html_body:
        for match in re.finditer(r'<link[^>]+rel\s*=\s*["\'][^"\']*manifest[^"\']*["\'][^>]+href\s*=\s*["\']([^"\']+)["\']', html_body, re.IGNORECASE):
            candidates.append(match.group(1))
    candidates.append(base_url.rstrip("/") + "/manifest.json")
    seen: set[str] = set()
    for candidate in candidates:
        absolute = candidate if candidate.startswith(("http://", "https://")) else urljoin(base_url, candidate)
        if absolute in seen:
            continue
        seen.add(absolute)
        if not is_safe_url(absolute):
            continue
        body = _fetch_text_content(absolute, 6, 250_000)
        if not body:
            continue
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            continue
        result["manifest_url"] = absolute
        result["discovered"] = True
        result["raw"] = data
        result["start_url"] = data.get("start_url")
        result["scope"] = data.get("scope")
        result["related_applications"] = data.get("related_applications", []) or []
        result["shortcuts"] = data.get("shortcuts", []) or []
        if result["start_url"]:
            if result["start_url"].startswith("http://") or result["start_url"].startswith("https://"):
                start_netloc = urlparse(result["start_url"]).netloc.lower()
                base_netloc = urlparse(base_url).netloc.lower()
                if start_netloc != base_netloc:
                    result["external_start_url"] = True
                    result["warnings"].append(f"start_url {result['start_url']} is on a different origin")
        break
    return result


def _resolve_template_to_pattern(text: str) -> str:
    """Replace ``${expr}`` placeholders with ``{param}`` for safe URL emission.

    The output is suitable for use in the recon URL set — when a
    crawler / Nuclei sees the ``{param}`` token, nuclei templates
    that match on path patterns (e.g. ``/users/{param}/orders``) fire.
    """
    return re.sub(r"\$\{[^}]+\}", "{param}", text or "")


def _resolve_call_endpoint(arg_expr: str, base_url: str) -> str | None:
    """Convert a fetch-like first argument to an absolute URL.

    Handles:
      * Plain string literals: ``"/api/users"``
      * Template literals:   ```/users/${id}` → /users/{param}``
      * String concat:       ``"/api/" + kind + "/list"`` (best effort)
      * URL literals:        ``"https://api.example.com/x"``

    Returns None when the expression does not contain a usable string.
    """
    if not arg_expr:
        return None
    string_match = re.search(r"""(['"`])((?:\\.|(?!\1).)*)\1""", arg_expr, re.DOTALL)
    if string_match:
        inner = string_match.group(2)
        normalized = _resolve_template_to_pattern(inner)
        return _candidate_to_absolute_url(normalized, base_url)
    concat_match = re.match(
        r"^(['\"`])([^'\"`]+)\1\s*\+\s*[A-Za-z_$][\w$]*", arg_expr
    )
    if concat_match:
        prefix = concat_match.group(2)
        normalized = _resolve_template_to_pattern(prefix) + "{param}"
        return _candidate_to_absolute_url(normalized, base_url)
    return None


def extract_endpoints_v2(
    content: str,
    base_url: str,
    scope_roots: set[str],
) -> set[str]:
    """Run the v2 (AST-aware + WebSocket + HTML attr) extraction pipeline.

    Args:
        content: Raw HTML or JS body.
        base_url: Base URL for resolving relative paths.
        scope_roots: Set of allowed root domains for scope filtering.

    Returns:
        Set of absolute in-scope URLs / paths discovered.
    """
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
