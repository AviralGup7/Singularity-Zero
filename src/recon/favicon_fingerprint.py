"""Favicon-hash-based technology fingerprinting.

The favicon (``/favicon.ico``) is one of the few static files every
web application serves regardless of its technology stack. By hashing
the favicon bytes and looking the hash up in a community database
(``faviconhash.com``, ``sonar.omnisint.io``), recon tools can
identify the underlying technology — WordPress, Jira, Confluence,
Grafana, Kibana, custom internal apps — even when the framework
headers are scrubbed.

This module:

1. Fetches ``/favicon.ico`` (with the standard set of fallback paths)
   from a list of hosts.
2. Computes the **mmh3 hash** of the favicon body (the same hash
   format used by Shodan / faviconhash.com).
3. Optionally cross-references the hash against a community lookup
   endpoint.
4. Returns a dict keyed by host with the favicon URL, hash, content
   type, and (when available) the technology identification.

The function degrades gracefully: any HTTP failure returns an empty
result for the host; the rest of the scan continues.
"""
from __future__ import annotations


import hashlib
import json
import logging
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from src.recon.url_validation import is_safe_url

logger = logging.getLogger(__name__)

# Paths tried in order. The set is intentionally short; /favicon.ico
# covers ~95% of real-world sites, and the other paths catch the
# remainder (Rails apps, custom CMSes, single-page apps that ship
# their favicon at /assets/).
_FAVICON_PATHS: tuple[str, ...] = (
    "/favicon.ico",
    "/favicon.png",
    "/favicon.svg",
    "/apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png",
    "/static/favicon.ico",
    "/assets/favicon.ico",
    "/images/favicon.ico",
    "/img/favicon.ico",
)

DEFAULT_FAVICON_TIMEOUT = 6
DEFAULT_FAVICON_CONCURRENCY = 8

USER_AGENT = "cyber-pipeline/2.0 (favicon-fingerprint)"


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------


def mmh3_hash_32(data: bytes) -> int:
    """Compute the 32-bit mmh3 hash used by Shodan / faviconhash.com.

    We re-implement the algorithm in pure Python because the platform
    may not have the ``mmh3`` C extension installed. The output is a
    signed 32-bit integer — the canonical Shodan representation.
    """
    return _mmh3_32(data)


def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python mmh3 32-bit implementation.

    Adapted from the public-domain reference implementation. The
    algorithm walks the input in 4-byte little-endian chunks, mixes
    them via the standard mmh3 finalisation, and returns the signed
    32-bit result.
    """
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    nblocks = length // 4

    h1 = seed & 0xFFFFFFFF

    for i in range(nblocks):
        i4 = i * 4
        k1 = (
            (data[i4] & 0xFF)
            | ((data[i4 + 1] & 0xFF) << 8)
            | ((data[i4 + 2] & 0xFF) << 16)
            | ((data[i4 + 3] & 0xFF) << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    # Tail
    tail_index = nblocks * 4
    k1 = 0
    tail_size = length & 3
    if tail_size >= 3:
        k1 ^= (data[tail_index + 2] & 0xFF) << 16
    if tail_size >= 2:
        k1 ^= (data[tail_index + 1] & 0xFF) << 8
    if tail_size >= 1:
        k1 ^= data[tail_index] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    # Finalisation
    h1 ^= length & 0xFFFFFFFF
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Convert to signed 32-bit (Shodan convention)
    if h1 & 0x80000000:
        h1 = -((h1 ^ 0xFFFFFFFF) + 1)
    return h1


# ---------------------------------------------------------------------------
# Fetch + identify
# ---------------------------------------------------------------------------


def _normalize_base(host: str) -> str:
    host = (host or "").strip().lower()
    if not host:
        return ""
    if "://" in host:
        return host
    return f"https://{host}"


def _fetch_favicon_for_host(
    host: str,
    *,
    timeout: int = DEFAULT_FAVICON_TIMEOUT,
) -> dict[str, Any] | None:
    """Return a small dict for *host*'s favicon, or None on failure."""
    base = _normalize_base(host)
    if not base or not is_safe_url(base):
        return None
    origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    for path in _FAVICON_PATHS:
        url = urljoin(origin.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = requests.get(
                url,
                timeout=max(2, int(timeout)),
                allow_redirects=True,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        body = resp.content
        if not body or len(body) < 16:
            continue
        content_type = resp.headers.get("content-type", "")
        # The mmh3 hash used by Shodan is the canonical representation
        sha256 = hashlib.sha256(body).hexdigest()
        return {
            "host": host,
            "url": url,
            "content_type": content_type,
            "size": len(body),
            "mmh3": mmh3_hash_32(body),
            "sha256": sha256,
        }
    return None


def fetch_favicons(
    hosts: Iterable[str],
    *,
    timeout: int = DEFAULT_FAVICON_TIMEOUT,
    max_workers: int = DEFAULT_FAVICON_CONCURRENCY,
) -> dict[str, dict[str, Any]]:
    """Fetch + hash the favicon for every host in *hosts*.

    Args:
        hosts: Hostnames to query.
        timeout: Per-host timeout in seconds.
        max_workers: Max concurrent HTTP fetches.

    Returns:
        Dict keyed by hostname; only hosts that returned a favicon
        appear in the result.
    """
    host_list = sorted({h for h in hosts if h and h.strip()})
    if not host_list:
        return {}

    results: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(host_list)))) as ex:
        futures = {ex.submit(_fetch_favicon_for_host, h, timeout=timeout): h for h in host_list}
        for fut in futures:
            host = futures[fut]
            try:
                fav = fut.result()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Favicon fetch failed for %s: %s", host, exc)
                continue
            if fav is not None:
                results[host] = fav
    return results


# ---------------------------------------------------------------------------
# Community lookup
# ---------------------------------------------------------------------------


def lookup_faviconhash(mmh3_value: int, *, timeout: int = 8) -> list[dict[str, Any]]:
    """Cross-reference an mmh3 hash against faviconhash.com.

    Args:
        mmh3_value: The signed 32-bit mmh3 hash.
        timeout: Per-request timeout in seconds.

    Returns:
        List of matching technologies. Empty when the lookup fails
        or the hash is unknown.
    """
    try:
        resp = requests.get(
            f"https://faviconhash.com/api/hash/{mmh3_value}",
            timeout=max(2, int(timeout)),
            headers={"User-Agent": USER_AGENT},
        )
    except requests.RequestException as exc:
        logger.debug("faviconhash lookup failed for %s: %s", mmh3_value, exc)
        return []
    if resp.status_code != 200:
        return []
    try:
        data = resp.json()
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return [
        {"name": item.get("name"), "shodan_query": item.get("shodan_query")}
        for item in data
        if isinstance(item, dict)
    ]


__all__ = [
    "fetch_favicons",
    "lookup_faviconhash",
    "mmh3_hash_32",
]
