"""Depth-limited crawler for in-house URL collection.

This crawler is intentionally small and deterministic: it performs a
breadth-first crawl per-host up to a page limit, extracts links and
script references, and optionally fetches JS files to extract endpoint
candidates. It returns a set of normalized URLs and a metadata dict.
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
from bs4 import BeautifulSoup

from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.observability import emit_collection_progress
from src.recon.common import normalize_scope_entry, normalize_url

logger = logging.getLogger(__name__)

# Crawler behavior constants
# 2 seconds is chosen to prevent the crawler from hanging on slow targets. Since the crawler
# makes thousands of requests, a higher timeout would severely degrade pipeline performance.
CRAWL_TIMEOUT_SECONDS = 2

# Limit JS file parsing to 10 per host to prevent CPU exhaustion on single-page apps
# that bundle hundreds of massive, minified chunk files.
MAX_JS_FILES_PER_HOST = 10


# Simple JS endpoint pattern (captures common absolute and relative forms)
_JS_ENDPOINT_RE = re.compile(
    r"['\"]("
    r"(?:https?:)?//[^'\"\\\s]{4,}"
    r"|/[A-Za-z0-9][^'\"\\\s]{1,}"
    r"|\./[A-Za-z0-9][^'\"\\\s]{1,}"
    r"|\.\./[A-Za-z0-9][^'\"\\\s]{1,}"
    r"|[A-Za-z0-9_\-./]{2,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^'\"\\\s]*)?"
    r")['\"]",
    re.IGNORECASE,
)


def _normalized_scope_roots(scope_entries: Iterable[str]) -> set[str]:
    roots: set[str] = set()
    for entry in scope_entries or []:
        normalized = normalize_scope_entry(entry).strip().lower().lstrip("*.")
        if normalized:
            roots.add(normalized)
    return roots


def _is_in_scope_url(url: str, scope_roots: set[str]) -> bool:
    if not scope_roots:
        return True
    hostname = (urlparse(url).hostname or "").strip().lower()
    if not hostname:
        return False
    return any(hostname == root or hostname.endswith(f".{root}") for root in scope_roots)


def _candidate_to_absolute_url(candidate: str, base_url: str) -> str | None:
    cleaned = (candidate or "").strip().strip("\"'")
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


def _extract_links_from_html(html: str, base_url: str, scope_roots: set[str]) -> set[str]:
    urls: set[str] = set()
    try:
        soup = BeautifulSoup(html or "", "html.parser")
    except Exception:
        return urls

    for tag in soup.find_all("a", href=True):
        href = tag.get("href") or ""
        absolute = _candidate_to_absolute_url(href, base_url)
        if absolute and _is_in_scope_url(absolute, scope_roots):
            urls.add(absolute)

    for tag in soup.find_all("link", href=True):
        href = tag.get("href") or ""
        absolute = _candidate_to_absolute_url(href, base_url)
        if absolute and _is_in_scope_url(absolute, scope_roots):
            urls.add(absolute)

    # script src attributes
    for tag in soup.find_all("script", src=True):
        src = tag.get("src") or ""
        absolute = _candidate_to_absolute_url(src, base_url)
        if absolute and _is_in_scope_url(absolute, scope_roots):
            urls.add(absolute)

    return urls


def _extract_js_candidates_from_text(text: str, base_url: str, scope_roots: set[str]) -> set[str]:
    discovered: set[str] = set()
    if not text:
        return discovered
    for match in _JS_ENDPOINT_RE.finditer(text):
        raw = (match.group(1) or "").strip()
        absolute = _candidate_to_absolute_url(raw, base_url)
        if absolute and _is_in_scope_url(absolute, scope_roots):
            discovered.add(absolute)
    return discovered


def _fetch_text(url: str, timeout_seconds: int) -> str:
    try:
        resp = requests.get(
            url,
            timeout=max(CRAWL_TIMEOUT_SECONDS, timeout_seconds),
            headers={"User-Agent": "target-specific-pipeline/2.0"},
        )
        if resp.status_code >= 400:
            return ""
        content_type = str(resp.headers.get("content-type", "")).lower()
        if content_type and not any(
            token in content_type for token in ("text", "html", "javascript", "json", "ecmascript")
        ):
            return ""
        return resp.text or ""
    except requests.RequestException:
        return ""


def _crawl_single_host(
    base_url: str, timeout_seconds: int, max_pages: int, js_discovery: bool, scope_roots: set[str]
) -> tuple[set[str], dict[str, Any]]:
    """Crawl a single host using breadth-first search up to max_pages.

    Algorithm:
        1. Seed queue with base_url (https:// prefix added if missing).
        2. Pop URL from queue, skip if already visited.
        3. Fetch page text, extract links via _extract_links_from_html.
        4. Add new links to queue (BFS continues).
        5. Extract script URLs, optionally fetch JS content for endpoint discovery.
        6. Track pages_fetched, scripts_found, errors, and total discovered URLs.
        7. Stop when queue empty or max_pages reached.

    Args:
        base_url: Host to crawl (with or without scheme).
        timeout_seconds: Per-page fetch timeout.
        max_pages: Maximum pages to fetch per host.
        js_discovery: Whether to fetch and parse JS files for endpoints.
        scope_roots: Set of allowed host roots for filtering.

    Returns:
        Tuple of (discovered_urls_set, metadata_dict).
    """
    discovered: set[str] = set()
    queued: list[str] = []
    visited: set[str] = set()
    pages_fetched = 0
    scripts_found = 0
    errors = 0

    # seed queue with base_url
    seed = base_url if base_url.startswith(("http://", "https://")) else f"https://{base_url}"
    queued.append(seed)

    while queued and pages_fetched < max_pages:
        url = queued.pop(0)
        if url in visited:
            continue
        visited.add(url)

        collector_metrics.increment_requests("crawler")
        text = _fetch_text(url, timeout_seconds)
        if not text:
            errors += 1
            collector_metrics.increment_errors("crawler")
            continue

        pages_fetched += 1
        links = _extract_links_from_html(text, url, scope_roots)
        before = len(discovered)
        discovered.update(links)
        # queue new links for crawling (simple BFS)
        for link in sorted(links):
            if link not in visited and len(queued) + pages_fetched < max_pages:
                queued.append(link)

        # extract script urls and optionally fetch JS
        script_urls = set()
        try:
            soup = BeautifulSoup(text or "", "html.parser")
            for tag in soup.find_all("script", src=True):
                src = tag.get("src") or ""
                abs_src = _candidate_to_absolute_url(src, url)
                if abs_src and _is_in_scope_url(abs_src, scope_roots):
                    script_urls.add(abs_src)
        except Exception as e:
            logger.debug("Failed to parse script tag %s: %s", tag, e)

        scripts_found += len(script_urls)
        discovered.update(script_urls)

        if js_discovery:
            for js in sorted(script_urls)[: max(0, MAX_JS_FILES_PER_HOST)]:
                js_text = _fetch_text(js, timeout_seconds)
                if not js_text:
                    continue
                candidates = _extract_js_candidates_from_text(js_text, js, scope_roots)
                discovered.update(candidates)

        delta = len(discovered) - before
        if delta > 0:
            collector_metrics.increment_urls("crawler", delta)

    meta = {
        "status": "ok" if discovered else "empty",
        "duration_seconds": round(0.0, 1),
        "new_urls": len(discovered),
        "pages_fetched": pages_fetched,
        "scripts_found": scripts_found,
        "errors": errors,
    }
    return discovered, meta


def crawl_hosts(
    live_hosts: Iterable[str],
    scope_entries: Iterable[str] | None = None,
    timeout_seconds: int = 8,
    max_pages_per_host: int = 12,
    workers: int = 6,
    js_discovery: bool = False,
    progress_callback: Any | None = None,
) -> tuple[set[str], dict[str, Any]]:
    start = time.monotonic()
    hosts = [h for h in (live_hosts or []) if h]
    if not hosts:
        return set(), {"status": "empty", "duration_seconds": 0.0, "new_urls": 0}

    scope_roots = _normalized_scope_roots(scope_entries or [])
    discovered: set[str] = set()
    aggregate_meta = {}

    emit_collection_progress(progress_callback, f"Crawler: scanning {len(hosts)} hosts", 60)

    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as executor:
        futures = [
            executor.submit(
                _crawl_single_host,
                host,
                timeout_seconds,
                max_pages_per_host,
                js_discovery,
                scope_roots,
            )
            for host in hosts
        ]
        for idx, future in enumerate(futures, start=1):
            try:
                host_urls, meta = future.result()
            except Exception:
                host_urls, meta = (
                    set(),
                    {"status": "error", "duration_seconds": 0.0, "new_urls": 0, "errors": 1},
                )
            before = len(discovered)
            discovered.update(host_urls)
            aggregate_meta[f"host_{idx}"] = meta
            emit_collection_progress(
                progress_callback,
                f"crawler host {idx}/{len(hosts)}: +{len(discovered) - before} urls, total {len(discovered)}",
                60 + int((idx / len(hosts)) * 8),
                processed=idx,
                total=len(hosts),
            )

    duration = round(time.monotonic() - start, 1)
    collector_metrics.observe_duration("crawler", duration)
    return discovered, {
        "status": "ok" if discovered else "empty",
        "duration_seconds": duration,
        "new_urls": len(discovered),
    }
