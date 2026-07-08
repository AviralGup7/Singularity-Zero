"""Legacy JS parsing helpers (from original js_parsers.py)."""

from __future__ import annotations

import re

from src.recon.common import normalize_scope_entry
from src.recon.js_parsers.endpoints import _is_in_scope_url

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
        |(?<![A-Za-z0-9_/.\-])[A-Za-z0-9_\-./]{2,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^"'\\\s]*)?
    )(?:"|')""",
    re.IGNORECASE | re.VERBOSE,
)


def _normalized_scope_roots(scope_entries: list[str]) -> set[str]:
    """Convert scope entries to normalized lowercase root domains."""
    roots: set[str] = set()
    for entry in scope_entries:
        normalized = normalize_scope_entry(entry).strip().lower().lstrip("*.")
        if normalized:
            roots.add(normalized)
    return roots


from src.recon.js_parsers.regex_extractors import _candidate_to_absolute_url


def _extract_script_urls_from_html(
    html_body: str,
    base_url: str,
    scope_roots: set[str],
) -> set[str]:
    """Extract script src URLs from HTML using regex patterns."""
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
    """Identify template literals and Axios/Fetch patterns to extract parameterized/dynamic routes."""
    candidates: set[str] = set()

    for match in _TEMPLATE_LITERAL_RE.finditer(content):
        raw_literal = match.group(1)
        normalized = re.sub(r"\$\{[^}]+\}", "{param}", raw_literal)
        candidates.add(normalized)

    for match in _AXIOS_FETCH_RE.finditer(content):
        raw_route = match.group(1)
        normalized = re.sub(r"\$\{[^}]+\}", "{param}", raw_route)
        candidates.add(normalized)

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
    """Extract URL candidates from JS content using regex patterns."""
    discovered: set[str] = set()
    for match in _JS_ENDPOINT_RE.finditer(content):
        raw = (match.group(1) or "").strip()
        absolute = _candidate_to_absolute_url(raw, base_url)
        if absolute and _is_in_scope_url(absolute, scope_roots):
            discovered.add(absolute)

    ast_candidates = _extract_js_ast_endpoints(content)
    for raw in ast_candidates:
        safe_placeholder = "PARAMPLACEHOLDER"
        safe_raw = raw.replace("{param}", safe_placeholder)
        absolute = _candidate_to_absolute_url(safe_raw, base_url)
        if absolute and _is_in_scope_url(absolute, scope_roots):
            restored = absolute.replace(safe_placeholder, "{param}")
            discovered.add(restored)

    return discovered
