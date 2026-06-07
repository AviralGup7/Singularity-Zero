"""Lightweight in-house crawler provider to replace external `katana`.

This provider fetches root pages for hosts, extracts anchor ``href``
and script ``src`` references, resolves them to absolute URLs within
scope, normalizes results, and returns a set of discovered URLs along
with lightweight metadata.

Like the other providers in this package, the public surface now
returns a :class:`CollectorMeta` (dict-compatible) and exposes an
``iter_for_hosts`` generator that yields per-host results so the
streaming aggregator can interleave URLs from multiple providers at
host granularity.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Generator, Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.observability import emit_collection_progress
from src.recon.collectors.types import CollectorMeta, CollectorStatus
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


def _fetch_text(
    url: str,
    timeout_seconds: int,
    max_bytes: int,
    session: requests.Session | None = None,
) -> str:
    get_callable = session.get if session is not None else requests.get
    try:
        resp = get_callable(
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
    try:
        requested_max = int(max_bytes)
    except Exception:
        requested_max = 0
    if requested_max < 0:
        logger.debug("simplecrawler: negative max_bytes=%s; using default cap", max_bytes)
        requested_max = 0
    cap = max(4096, requested_max)
    return (resp.text or "")[:cap]


def _scan_host(
    base_url: str,
    timeout_seconds: int,
    max_bytes: int,
    scope_roots: set[str],
    session: requests.Session | None = None,
) -> set[str]:
    discovered: set[str] = set()
    html = _fetch_text(base_url, timeout_seconds, max_bytes, session=session)
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


def iter_for_hosts(
    hosts: Iterable[str],
    *,
    timeout_seconds: int = 12,
    per_host_limit: int = 1000,
    max_workers: int = 6,
    session: requests.Session | None = None,
    progress_callback: Any | None = None,
) -> Generator[tuple[str, set[str], CollectorMeta], None, CollectorMeta]:
    """Yield per-host ``(host, urls, host_meta)`` triples as each completes."""
    start = time.monotonic()
    hosts_list = [h for h in hosts if h]
    if not hosts_list:
        return CollectorMeta(
            status=CollectorStatus.EMPTY,
            new_urls=0,
            hosts_scanned=0,
            provider_name="crawler",
        )

    max_response_bytes = 120000
    scope_roots: set[str] = set()
    workers = min(max_workers, max(1, len(hosts_list)))
    errors = 0
    timeout_count = 0
    total_new = 0

    emit_collection_progress(progress_callback, f"Crawler: scanning {len(hosts_list)} hosts", 10)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_host = {
            executor.submit(
                _scan_host,
                host,
                timeout_seconds,
                max_response_bytes,
                scope_roots,
                session,
            ): host
            for host in hosts_list
        }
        idx = 0
        for future in future_to_host:
            idx += 1
            host = future_to_host[future]
            try:
                host_urls = future.result()
            except requests.Timeout:
                host_urls = set()
                errors += 1
                timeout_count += 1
            except Exception:
                host_urls = set()
                errors += 1

            host_meta = CollectorMeta(
                status=CollectorStatus.OK if host_urls else CollectorStatus.EMPTY,
                new_urls=len(host_urls),
                hosts_scanned=1,
                provider_name="crawler",
                extras={"host": host},
            )
            total_new += len(host_urls)
            emit_collection_progress(
                progress_callback,
                f"Crawler host {idx}/{len(hosts_list)}: +{len(host_urls)} urls, total {total_new}",
                10 + int((idx / len(hosts_list)) * 40),
                processed=idx,
                total=len(hosts_list),
            )
            yield host, host_urls, host_meta

    duration = round(time.monotonic() - start, 1)
    return CollectorMeta(
        status=CollectorStatus.OK if total_new else CollectorStatus.EMPTY,
        duration_seconds=duration,
        new_urls=total_new,
        errors=errors,
        timeout_count=timeout_count,
        hosts_scanned=len(hosts_list),
        provider_name="crawler",
    )


def collect_for_hosts(
    hosts: Iterable[str],
    timeout_seconds: int = 12,
    per_host_limit: int = 1000,
    max_workers: int = 6,
    progress_callback: Any | None = None,
    *,
    session: requests.Session | None = None,
) -> tuple[set[str], CollectorMeta]:
    discovered: set[str] = set()
    aggregate_meta: CollectorMeta
    gen = iter_for_hosts(
        hosts,
        timeout_seconds=timeout_seconds,
        per_host_limit=per_host_limit,
        max_workers=max_workers,
        session=session,
        progress_callback=progress_callback,
    )
    try:
        while True:
            _host, host_urls, _host_meta = next(gen)
            discovered.update(host_urls)
    except StopIteration as stop:
        aggregate_meta = stop.value  # type: ignore[assignment]

    aggregate_meta = aggregate_meta.with_updates(new_urls=len(discovered))
    return discovered, aggregate_meta


__all__ = ["collect_for_hosts", "iter_for_hosts"]
