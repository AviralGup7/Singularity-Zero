"""Lightweight in-house crawler provider to replace external `katana`.

This provider fetches root pages for hosts, extracts anchor `href` and
script `src` references, resolves them to absolute URLs within scope,
normalizes results, and returns a set of discovered URLs along with
lightweight metadata.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from src.recon.collectors.observability import emit_collection_progress
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)

_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)


def _candidate_to_absolute(candidate: str, base_url: str) -> str | None:
    c = (candidate or "").strip()
    c = c.strip('"').strip("'")
    if not c:
        return None
    lowered = c.lower()
    if lowered.startswith(("javascript:", "data:", "mailto:", "#")):
        return None
    if "{" in c or "}" in c:
        return None

    if c.startswith("//"):
        resolved = f"https:{c}"
    elif c.startswith(("http://", "https://")):
        resolved = c
    else:
        resolved = urljoin(base_url, c)

    parsed = urlparse(resolved)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return normalize_url(resolved)


def _fetch_text(url: str, timeout_seconds: int, max_bytes: int) -> str:
    try:
        resp = requests.get(
            url,
            timeout=max(2, timeout_seconds),
            allow_redirects=True,
            headers={"User-Agent": "target-specific-pipeline/2.0"},
        )
    except requests.RequestException:
        return ""
    if resp.status_code >= 400:
        return ""
    content_type = str(resp.headers.get("content-type", "")).lower()
    if content_type and not any(t in content_type for t in ("text", "html", "javascript", "json")):
        return ""
    return (resp.text or "")[: max(4096, max_bytes)]


def _scan_host(
    base_url: str, timeout_seconds: int, max_bytes: int, scope_roots: set[str]
) -> set[str]:
    discovered: set[str] = set()
    html = _fetch_text(base_url, timeout_seconds, max_bytes)
    if not html:
        return discovered

    for match in _HREF_RE.finditer(html):
        cand = match.group(1) or ""
        absolute = _candidate_to_absolute(cand, base_url)
        if absolute:
            hostname = (urlparse(absolute).hostname or "").lower()
            if not scope_roots or any(
                hostname == r or hostname.endswith(f".{r}") for r in scope_roots
            ):
                discovered.add(absolute)

    for match in _SCRIPT_SRC_RE.finditer(html):
        cand = match.group(1) or ""
        absolute = _candidate_to_absolute(cand, base_url)
        if absolute:
            hostname = (urlparse(absolute).hostname or "").lower()
            if not scope_roots or any(
                hostname == r or hostname.endswith(f".{r}") for r in scope_roots
            ):
                discovered.add(absolute)

    return discovered


def collect_for_hosts(
    hosts: Iterable[str],
    timeout_seconds: int = 12,
    per_host_limit: int = 1000,
    max_workers: int = 6,
    progress_callback: Any | None = None,
) -> tuple[set[str], dict[str, Any]]:
    start = time.monotonic()
    hosts_list = [h for h in hosts if h]
    if not hosts_list:
        return set(), {"status": "empty", "duration_seconds": 0.0, "new_urls": 0}

    discovered: set[str] = set()
    errors = 0
    max_response_bytes = 120000
    scope_roots = set()

    emit_collection_progress(progress_callback, f"Crawler: scanning {len(hosts_list)} hosts", 10)

    workers = min(max_workers, max(1, len(hosts_list)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_scan_host, h, timeout_seconds, max_response_bytes, scope_roots)
            for h in hosts_list
        ]
        for idx, future in enumerate(futures, start=1):
            try:
                host_urls = future.result()
            except Exception:
                host_urls = set()
                errors += 1
            before = len(discovered)
            discovered.update(host_urls)
            emit_collection_progress(
                progress_callback,
                f"Crawler host {idx}/{len(hosts_list)}: +{len(discovered) - before} urls, total {len(discovered)}",
                10 + int((idx / len(hosts_list)) * 40),
                processed=idx,
                total=len(hosts_list),
            )

    duration = round(time.monotonic() - start, 1)
    meta = {
        "status": "ok" if discovered else "empty",
        "duration_seconds": duration,
        "new_urls": len(discovered),
        "errors": errors,
    }
    return discovered, meta


__all__ = ["collect_for_hosts"]
