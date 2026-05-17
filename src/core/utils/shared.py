"""Shared URL and text normalization utilities.

Provides functions for normalizing scope entries, URLs, and parsing
plain text line lists into deduplicated sets.
"""

import logging
from urllib.parse import parse_qsl, urlencode, urlparse

logger = logging.getLogger(__name__)

__all__ = ["normalize_scope_entry", "normalize_url", "parse_plain_lines"]


def normalize_scope_entry(entry: str) -> str:
    """Remove wildcard prefix from a scope entry (e.g., '*.example.com' -> 'example.com').

    Args:
        entry: Scope entry string, optionally prefixed with '*.'.

    Returns:
        Scope entry with wildcard prefix removed if present.
    """
    return entry[2:] if entry.startswith("*.") else entry


def normalize_url(url: str) -> str:
    """
    Frontier URL Normalizer.
    Lowercases, sorts query params, strips trailing slashes, resolves path traversals,
    and normalizes standard ports for perfect distributed deduplication.
    """
    candidate = url.strip()
    if not candidate:
        return ""

    try:
        raw_parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
        scheme = (raw_parsed.scheme or "https").lower()
        netloc = raw_parsed.netloc.lower() or raw_parsed.path.lower()

        # 1. Standard Port Normalization
        if ":" in netloc:
            host, port = netloc.rsplit(":", 1)
            if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                netloc = host

        # 2. Path Canonicalization (Collapse slashes and resolve traversals)
        path = raw_parsed.path if netloc else ""
        import os

        cleaned_path = os.path.normpath(path).replace("\\", "/")  # cross-platform safety
        if cleaned_path == ".":
            cleaned_path = ""
        elif path.endswith("/") and not cleaned_path.endswith("/"):
            # normpath strips trailing slash, but we might want to preserve it if significant
            # however, for security scans, we typically normalize it away
            pass

        # 3. Query Normalization
        normalized_query = urlencode(
            sorted(parse_qsl(raw_parsed.query, keep_blank_values=True)), doseq=True
        )

        normalized = f"{scheme}://{netloc}"
        if cleaned_path and cleaned_path != "/":
            normalized += cleaned_path
        if normalized_query:
            normalized += f"?{normalized_query}"
        return normalized
    except (ValueError, AttributeError) as exc:
        logger.debug("Frontier: Failed to normalize URL %r: %s", url, exc)
        return candidate


def parse_plain_lines(text: str) -> set[str]:
    """Parse plain text lines into a deduplicated set of normalized values.

    Lines containing '://' or '/' are treated as URLs and normalized.
    Other lines are lowercased and stripped.

    Args:
        text: Multi-line text to parse.

    Returns:
        Set of normalized values.
    """
    values = set()
    for line in text.splitlines():
        try:
            normalized = (
                normalize_url(line) if "://" in line or "/" in line else line.strip().lower()
            )
            if normalized:
                values.add(normalized)
        except Exception as exc:
            logger.debug("Skipping malformed line %r: %s", line, exc)
    return values
