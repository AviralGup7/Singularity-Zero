"""AST-aware JS endpoint / route extraction (v2).

The original ``js_parsers`` module relies on a small set of regex
patterns. That works for the simple case of ``axios.get("/users")`` but
misses huge swathes of modern framework code:

* **Multi-layer indirection** — ``api.get(`/users/${id}`)`` where
  ``api = axios.create(...)`` and ``get = (url) => axios.get(url)``.
* **Template literals with expressions** — ``/users/${userId}/posts``
  where the placeholder is not a simple ``${var}``.
* **WebSocket / EventSource URLs** — ``new WebSocket("wss://api/x")``
  contains significant attack surface but the previous code dropped
  non-http schemes.
* **Source maps** — webpack-style ``.map`` files contain the original
  source under ``sourcesContent``. The previous code re-ran the JS
  regex over the map body, which is useless because the map is JSON,
  not JS.
* **htmx / Alpine / Turbo** — these frameworks encode endpoints in
  HTML attributes (``hx-get``, ``x-on:fetch``, ``data-turbo-action``),
  not in JS.
* **GraphQL strings** — ``gql`query { user(id: 1) { name } }``` often
  embeds the full query in JS, which is a strong GraphQL signal.

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
from urllib.parse import urljoin, urlparse

from src.recon.url_validation import is_safe_url

# ---------------------------------------------------------------------------
# Inlined helpers (duplicated from src.recon.js_parsers to avoid the
# js_parsers -> src.recon.__init__ -> js_parsers_v2 circular chain that
# surfaces when the package __init__ runs during partial module loads).
# Keep these in sync with src.recon.js_parsers.
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# String / comment stripping
# ---------------------------------------------------------------------------


_STRING_RE = re.compile(
    r"""
    (?P<quote>(?P<ch>['"`]))
    (?:
        \\.               # escaped char
        |
        (?!(?P=ch))       # any char except the closing quote
        .
    )*?
    (?P=ch)
    """,
    re.VERBOSE | re.DOTALL,
)

# Block + line comments
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


# ---------------------------------------------------------------------------
# HTML attribute endpoint extraction (htmx, Alpine, Turbo)
# ---------------------------------------------------------------------------


# htmx: hx-get, hx-post, hx-put, hx-patch, hx-delete, hx-connect
_HTMX_RE = re.compile(
    r'\bhx-(?:get|post|put|patch|delete|connect|target|include|vals|boost|ws|ws-connect|sse)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Alpine: x-data with fetch() calls, x-init, @click="fetch('/x')"
_ALPINE_RE = re.compile(
    r'(?:x-on:|@)([a-zA-Z][\w-]*)\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)

# Turbo / Hotwire: data-turbo-action, data-turbo-method
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


# ---------------------------------------------------------------------------
# WebSocket / EventSource URL extraction
# ---------------------------------------------------------------------------


_WEBSOCKET_RE = re.compile(
    r"""(?:new\s+(?:WebSocket|EventSource|SSE)\s*\(\s*['"`]|io\s*\(\s*['"`]|socket\s*\(\s*['"`])(wss?://[^'"`\s]+)""",
    re.IGNORECASE,
)

# socket.io connect: io("https://api/x", { ... }) — second-arg is config
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


# ---------------------------------------------------------------------------
# AST-aware call extraction
# ---------------------------------------------------------------------------


# Callee names we treat as "fetch-like". Matched case-insensitively,
# optionally chained: ``axios.get``, ``http.get``, ``api.fetch``.
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
                # pass through escape
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
        # ``fetch``/``axios``/etc. take a URL as their first argument;
        # ``api(url, config)`` patterns also fit.
        first = first_args[0]
        if first:
            candidates.append(first)
    return candidates


# ---------------------------------------------------------------------------
# Source map de-mangling
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Endpoint resolution
# ---------------------------------------------------------------------------


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
    # Plain string
    string_match = re.search(r"""(['"`])((?:\\.|(?!\1).)*)\1""", arg_expr, re.DOTALL)
    if string_match:
        inner = string_match.group(2)
        normalized = _resolve_template_to_pattern(inner)
        return _candidate_to_absolute_url(normalized, base_url)
    # Concat of a string + identifier: '/api/v1/' + userId
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

    # 1. AST-aware fetch-like call extraction. We run the parser on a
    #    string-stripped copy so balanced paren walking is robust to
    #    nested comments / regex noise, then we *also* run it on the raw
    #    content so plain string-literal first arguments (the most
    #    common case) survive. The dedupe in ``discovered`` is order-
    #    preserving so callers get deterministic results.
    stripped = _strip_strings_and_comments(content)
    for arg_expr in extract_endpoint_calls(stripped):
        resolved = _resolve_call_endpoint(arg_expr, base_url)
        if resolved and _is_in_scope_url(resolved, scope_roots):
            discovered.add(resolved)
    for arg_expr in extract_endpoint_calls(content):
        resolved = _resolve_call_endpoint(arg_expr, base_url)
        if resolved and _is_in_scope_url(resolved, scope_roots):
            discovered.add(resolved)

    # 2. WebSocket / EventSource / socket.io (uses raw content)
    for url in extract_websocket_endpoints(content):
        # WebSocket URLs are kept even if they target external hosts —
        # these are the most interesting "where else does this app
        # talk to" findings and we always emit them. The caller can
        # still filter by scope if desired.
        discovered.add(url)

    # 3. HTML attribute endpoints (htmx / Alpine / Turbo)
    for value in extract_html_attribute_endpoints(content):
        resolved = _candidate_to_absolute_url(value, base_url)
        if resolved and _is_in_scope_url(resolved, scope_roots):
            discovered.add(resolved)

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
    "extract_endpoint_calls",
    "extract_endpoints_v2",
    "extract_html_attribute_endpoints",
    "extract_source_map_url",
    "extract_sources_content",
    "extract_websocket_endpoints",
    "is_source_map_body",
]
