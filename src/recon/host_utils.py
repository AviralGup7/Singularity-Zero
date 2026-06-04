"""Shared helpers for parsing and normalising host names.

This module consolidates host-extraction helpers that were previously
duplicated across ``subdomains.py``, ``live_hosts.py``, ``nuclei.py``,
``ranking_support.py``, and ``urls.py``. Each of those copies computed
the host slightly differently, which caused false negatives in WAF
grouping, FP dedup, and takeover detection.
"""

from __future__ import annotations

from urllib.parse import urlparse


def host_from_url(value: object) -> str:
    """Return the lowercased ``host[:port]`` for a URL string.

    Examples:
        >>> host_from_url("https://Example.com:8080/foo")
        'example.com:8080'
        >>> host_from_url("example.com")
        'example.com'
        >>> host_from_url(None)
        ''
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        # No scheme — treat the input as a bare host
        return text.lower()
    try:
        parsed = urlparse(text)
    except ValueError:
        return text.lower()
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return ""
    port = parsed.port
    if port:
        return f"{hostname}:{port}"
    return hostname


def hostname_only(value: object) -> str:
    """Return just the hostname (no port) lowercased."""
    full = host_from_url(value)
    if not full:
        return ""
    # Strip bracketed IPv6 first
    if full.startswith("["):
        end = full.find("]")
        if end != -1:
            return full[1:end].lower()
    return full.split(":", 1)[0].lower()


def extract_host_candidate(value: object) -> str:
    """Best-effort host extraction from a URL or bare host string.

    Used by parameter-value extraction where the input might be a
    hostname, a partial URL, or a fully-qualified URL.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        return host_from_url(text)
    if "/" in text:
        # Looks like ``example.com/path``
        return hostname_only(f"http://{text}")
    # ``host:port`` has exactly one colon; IPv6 literals have many.
    # The previous expression ``not text.count(":") > 1`` parsed as
    # ``not (count > 1)`` and accidentally let IPv6 strings fall through
    # to ``text.lower()``, returning the literal as a "hostname".
    if ":" in text and text.count(":") <= 1:
        return hostname_only(text)
    # Bracketed IPv6 literal or bare ``::1``-style address: extract hostname.
    if text.startswith("[") or text.count(":") > 1:
        return hostname_only(text if text.startswith("[") else f"[{text}]")
    return text.lower()
