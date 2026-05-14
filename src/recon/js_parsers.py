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
    return discovered
