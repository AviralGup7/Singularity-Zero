"""JS parsing helpers for JS endpoint discovery.

This module contains regexes and extraction helpers used by
`js_discovery` for turning HTML/JS text into candidate URLs.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from src.recon.common import normalize_scope_entry, normalize_url

# Patterns used for extracting script srcs and JS endpoints
_SCRIPT_SRC_RE = re.compile(r"<script[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>", re.IGNORECASE)
_DYNAMIC_IMPORT_RE = re.compile(
    r"(?:import\s*\(\s*[\"']|require\s*\(\s*[\"'])([^\"']+)[\"']", re.IGNORECASE
)
_JS_ENDPOINT_RE = re.compile(
    r"""(?:"|')(
        (?:https?:)?//[^"'\\\s]{4,}
        |/[A-Za-z0-9][^"'\\\s]{1,}
        |\./[A-Za-z0-9][^"'\\\s]{1,}
        |\.\./[A-Za-z0-9][^"'\\\s]{1,}
        |[A-Za-z0-9_\-./]{2,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^"'\\\s]*)?
    )(?:"|')""",
    re.IGNORECASE | re.VERBOSE,
)


def _normalized_scope_roots(scope_entries: list[str]) -> set[str]:
    """Convert scope entries to normalized lowercase root domains.

    Args:
        scope_entries: List of scope entry strings (may include wildcards).

    Returns:
        Set of normalized root domain strings.
    """
    roots: set[str] = set()
    for entry in scope_entries:
        normalized = normalize_scope_entry(entry).strip().lower().lstrip("*.")
        if normalized:
            roots.add(normalized)
    return roots


def _is_in_scope_url(url: str, scope_roots: set[str]) -> bool:
    """Check if URL hostname matches any scope root or subdomain thereof.

    Args:
        url: URL to check.
        scope_roots: Set of allowed root domains.

    Returns:
        True if URL is in scope, False otherwise.
    """
    if not scope_roots:
        return True
    hostname = (urlparse(url).hostname or "").strip().lower()
    if not hostname:
        return False
    return any(hostname == root or hostname.endswith(f".{root}") for root in scope_roots)


def _candidate_to_absolute_url(candidate: str, base_url: str) -> str | None:
    """Convert a URL candidate to an absolute URL based on base_url.

    Handles relative paths (./, ../, /), protocol-relative (//), and
    absolute URLs. Filters out javascript:, data:, mailto:, and
    template placeholders ({, }).

    Args:
        candidate: URL string from HTML/JS extraction.
        base_url: Base URL for resolving relative paths.

    Returns:
        Normalized absolute URL or None if invalid/filtered.
    """
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
    return normalize_url(resolved)


def _extract_script_urls_from_html(
    html_body: str,
    base_url: str,
    scope_roots: set[str],
) -> set[str]:
    """Extract script src URLs from HTML using regex patterns.

    Searches for <script src="..."> and dynamic import patterns
    (import(...), require(...)) in the HTML body.

    Args:
        html_body: Raw HTML string.
        base_url: Base URL for resolving relative script paths.
        scope_roots: Set of allowed root domains.

    Returns:
        Set of absolute in-scope script URLs.
    """
    urls: set[str] = set()
    for pattern in (_SCRIPT_SRC_RE, _DYNAMIC_IMPORT_RE):
        for match in pattern.finditer(html_body):
            raw = (match.group(1) or "").strip()
            absolute = _candidate_to_absolute_url(raw, base_url)
            if absolute and _is_in_scope_url(absolute, scope_roots):
                urls.add(absolute)
    return urls


# Patterns for AST-like extraction of dynamic and parameterized routes
_TEMPLATE_LITERAL_RE = re.compile(r"`([^`\n]*?\$\{[^`\n]+?\}[^`\n]*?)`")
_AXIOS_FETCH_RE = re.compile(
    r"(?:\b(?:axios(?:\.get|\.post|\.put|\.delete|\.patch)?|fetch)|\$\.ajax|\$\.get|\$\.post)\(\s*['\"`]([^'\"`\s)]+)['\"`]",
    re.IGNORECASE,
)
_CONCAT_ROUTE_RE = re.compile(
    r"['\"](/[a-zA-Z0-9_\-/]+)['\"]\s*\+\s*[a-zA-Z0-9_]+(?:[a-zA-Z0-9_\-\s+]*['\"]([a-zA-Z0-9_\-/]*)['\"])?"
)


def _extract_js_ast_endpoints(content: str) -> set[str]:
    """Identify template literals and Axios/Fetch patterns to extract parameterized/dynamic routes.

    Args:
        content: Raw JavaScript content.

    Returns:
        Set of relative or absolute candidate routes.
    """
    candidates: set[str] = set()

    # 1. Parse template literals and replace `${var}` placeholders with `{param}`
    for match in _TEMPLATE_LITERAL_RE.finditer(content):
        raw_literal = match.group(1)
        normalized = re.sub(r"\$\{[^}]+\}", "{param}", raw_literal)
        candidates.add(normalized)

    # 2. Capture routes inside axios/fetch/ajax invocations
    for match in _AXIOS_FETCH_RE.finditer(content):
        raw_route = match.group(1)
        normalized = re.sub(r"\$\{[^}]+\}", "{param}", raw_route)
        candidates.add(normalized)

    # 3. Handle simple string concatenations like '/api/v1/' + userId
    for match in _CONCAT_ROUTE_RE.finditer(content):
        prefix = match.group(1).rstrip("/")
        suffix = match.group(2) or ""
        normalized = f"{prefix}/{{param}}{suffix}"
        candidates.add(normalized)

    return candidates


def _extract_js_candidate_urls(
    content: str,
    base_url: str,
    scope_roots: set[str],
) -> set[str]:
    """Extract URL candidates from JS content using regex patterns.

    Searches for absolute URLs, relative paths, and common endpoint
    file extensions (.php, .asp, .jsp, .json, .html, .js, etc.)
    within quoted strings in JS content.

    Args:
        content: Raw JS/text content to search.
        base_url: Base URL for resolving relative paths.
        scope_roots: Set of allowed root domains.

    Returns:
        Set of absolute in-scope URLs extracted from JS content.
    """
    discovered: set[str] = set()
    for match in _JS_ENDPOINT_RE.finditer(content):
        raw = (match.group(1) or "").strip()
        absolute = _candidate_to_absolute_url(raw, base_url)
        if absolute and _is_in_scope_url(absolute, scope_roots):
            discovered.add(absolute)

    # Deep AST/Dynamic patterns extraction
    ast_candidates = _extract_js_ast_endpoints(content)
    for raw in ast_candidates:
        # Replace '{param}' with a valid alphanumeric placeholder to bypass standard filters
        safe_placeholder = "PARAMPLACEHOLDER"
        safe_raw = raw.replace("{param}", safe_placeholder)
        absolute = _candidate_to_absolute_url(safe_raw, base_url)
        if absolute and _is_in_scope_url(absolute, scope_roots):
            # Restore the `{param}` syntax in the resolved absolute URL
            restored = absolute.replace(safe_placeholder, "{param}")
            discovered.add(restored)

    return discovered
