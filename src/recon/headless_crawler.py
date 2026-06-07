"""Headless-browser SPA crawler (Playwright fallback for Katana).

Modern Single-Page Applications (React, Vue, Angular, Svelte, Next.js)
do not render their routes in the initial HTML. The default crawler
(:mod:`src.recon.collectors.providers.crawler`) is a simple
``requests`` + ``BeautifulSoup`` walker that only sees the initial
document — the routes it discovers are limited to whatever the server
returns on the first request.

When Katana is unavailable, this module provides a headless-browser
fallback using Playwright. It:

1. Navigates to each host's root URL.
2. Waits for the SPA to hydrate (network idle, configurable).
3. Discovers in-page navigation targets via the same
   :func:`spa_detection.detect_frameworks_from_content` used in
   pipeline planning.
4. Clicks through internal links up to a configurable depth/page
   budget per host, capturing every URL the browser requests.
5. Returns the union of all observed URLs as the SPA-aware endpoint
   set.

The module degrades gracefully: if Playwright is not installed, every
call returns an empty set and the orchestrator falls back to the
existing crawler.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from src.recon.collectors.observability import emit_collection_progress
from src.recon.url_validation import is_safe_url

logger = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]

    HAS_PLAYWRIGHT = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_PLAYWRIGHT = False

# Default per-host budget for the headless crawl.
DEFAULT_MAX_PAGES_PER_HOST = 25

# Default per-page navigation budget (seconds).
DEFAULT_PAGE_TIMEOUT_SECONDS = 15

# Default depth — number of in-app link clicks to follow.
DEFAULT_MAX_DEPTH = 2

# Default concurrent browser instances.
DEFAULT_BROWSER_CONCURRENCY = 2


def _normalize_base(host: str) -> str:
    host = (host or "").strip().lower()
    if not host:
        return ""
    if "://" in host:
        return host
    return f"https://{host}"


def headless_crawl_host(
    host: str,
    *,
    max_pages: int = DEFAULT_MAX_PAGES_PER_HOST,
    page_timeout_seconds: int = DEFAULT_PAGE_TIMEOUT_SECONDS,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> set[str]:
    """Crawl a single host with a headless browser.

    Args:
        host: Hostname or base URL.
        max_pages: Cap on the number of internal pages visited.
        page_timeout_seconds: Per-page navigation timeout.
        max_depth: Cap on the number of in-app link clicks to follow.

    Returns:
        Set of absolute URLs observed during the crawl. Empty when
        Playwright is not installed.
    """
    if not HAS_PLAYWRIGHT:
        return set()
    base = _normalize_base(host)
    if not base or not is_safe_url(base):
        return set()
    origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"

    discovered: set[str] = set()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                context = browser.new_context(
                    ignore_https_errors=False,
                    user_agent=(
                        "Mozilla/5.0 (compatible; cyber-pipeline/2.0; "
                        "+https://github.com/cyber-pipeline)"
                    ),
                )
                page = context.new_page()
                # Track every URL the browser requests (main frame,
                # sub-frames, XHR/fetch). These URLs are exactly the
                # modern SPA endpoint surface.
                requested: set[str] = set()

                def _on_request(request: Any) -> None:
                    try:
                        url = request.url
                    except Exception:  # noqa: BLE001
                        return
                    if not url or not is_safe_url(url):
                        return
                    requested.add(url)

                page.on("request", _on_request)

                try:
                    page.goto(base, wait_until="networkidle", timeout=page_timeout_seconds * 1000)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Headless navigation failed for %s: %s", base, exc)
                discovered.update(requested)

                # Discover in-page links from the current DOM
                hrefs: list[str] = []
                try:
                    anchors = page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)"
                    )
                    if isinstance(anchors, list):
                        hrefs = [h for h in anchors if isinstance(h, str)]
                except Exception:  # noqa: BLE001
                    pass

                # BFS the link graph up to ``max_depth`` and ``max_pages``
                visited: set[str] = {base}
                queue: list[tuple[str, int]] = [(base, 0)]
                pages_visited = 0
                while queue and pages_visited < max_pages:
                    current_url, depth = queue.pop(0)
                    if depth >= max_depth:
                        continue
                    for href in hrefs:
                        absolute = urljoin(current_url, href)
                        if not is_safe_url(absolute):
                            continue
                        if not absolute.startswith(origin):
                            continue
                        if absolute in visited:
                            continue
                        visited.add(absolute)
                        try:
                            page.goto(
                                absolute,
                                wait_until="domcontentloaded",
                                timeout=page_timeout_seconds * 1000,
                            )
                            pages_visited += 1
                        except Exception:  # noqa: BLE001
                            continue
                        discovered.update(requested)
                        if depth + 1 < max_depth:
                            queue.append((absolute, depth + 1))
                        if pages_visited >= max_pages:
                            break
                context.close()
            finally:
                browser.close()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Headless crawl failed for %s: %s", host, exc)
    return discovered


def headless_crawl_hosts(
    hosts: Iterable[str],
    *,
    max_pages_per_host: int = DEFAULT_MAX_PAGES_PER_HOST,
    page_timeout_seconds: int = DEFAULT_PAGE_TIMEOUT_SECONDS,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_workers: int = DEFAULT_BROWSER_CONCURRENCY,
    progress_callback: Any = None,
) -> tuple[set[str], dict[str, Any]]:
    """Run a headless crawl across a list of hosts concurrently.

    Args:
        hosts: Hostnames or base URLs.
        max_pages_per_host: Per-host page budget.
        page_timeout_seconds: Per-page navigation timeout.
        max_depth: Per-host link-following depth.
        max_workers: Max concurrent browser instances.
        progress_callback: Optional observability hook.

    Returns:
        Tuple of (urls_set, meta). ``meta`` is a JSON-serialisable dict
        with counts, status, and durations.
    """
    if not HAS_PLAYWRIGHT:
        return set(), {
            "status": "playwright_unavailable",
            "duration_seconds": 0.0,
            "new_urls": 0,
            "hosts_scanned": 0,
        }

    hosts_list = [h for h in hosts if h]
    if not hosts_list:
        return set(), {"status": "empty", "duration_seconds": 0.0, "new_urls": 0}

    start = time.monotonic()
    discovered: set[str] = set()
    errors = 0

    emit_collection_progress(
        progress_callback,
        f"Headless SPA crawl: scanning {len(hosts_list)} hosts",
        65,
    )
    workers = max(1, min(max_workers, len(hosts_list)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [
            ex.submit(
                headless_crawl_host,
                host,
                max_pages=max_pages_per_host,
                page_timeout_seconds=page_timeout_seconds,
                max_depth=max_depth,
            )
            for host in hosts_list
        ]
        for idx, fut in enumerate(futures, start=1):
            try:
                urls = fut.result()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Headless crawl future failed: %s", exc)
                urls = set()
                errors += 1
            before = len(discovered)
            discovered.update(urls)
            delta = len(discovered) - before
            if hosts_list:
                emit_collection_progress(
                    progress_callback,
                    f"Headless crawl host {idx}/{len(hosts_list)}: +{delta} urls, total {len(discovered)}",
                    65 + int((idx / len(hosts_list)) * 2),
                    processed=idx,
                    total=len(hosts_list),
                )

    duration = round(time.monotonic() - start, 1)
    meta = {
        "status": "ok" if discovered else "empty",
        "duration_seconds": duration,
        "new_urls": len(discovered),
        "hosts_scanned": len(hosts_list),
        "errors": errors,
        "max_pages_per_host": max_pages_per_host,
        "max_depth": max_depth,
    }
    return discovered, meta


# ---------------------------------------------------------------------------
# Lightweight SPA-friendly HTTP crawler fallback (no Playwright required)
# ---------------------------------------------------------------------------


def simple_html_link_crawl(
    host: str,
    *,
    max_pages: int = DEFAULT_MAX_PAGES_PER_HOST,
    timeout_seconds: int = 6,
) -> set[str]:
    """Crawl internal links via plain HTTP (no JS execution).

    This is a much weaker fallback than :func:`headless_crawl_host` —
    it cannot execute client-side routing, so SPAs will look empty.
    It exists for environments where Playwright is not installable and
    the default crawler is also unavailable.
    """
    base = _normalize_base(host)
    if not base or not is_safe_url(base):
        return set()
    origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    visited: set[str] = {base}
    queue: list[str] = [base]
    discovered: set[str] = set()
    pages_visited = 0
    while queue and pages_visited < max_pages:
        url = queue.pop(0)
        try:
            resp = requests.get(
                url,
                timeout=max(2, timeout_seconds),
                allow_redirects=True,
                headers={"User-Agent": "cyber-pipeline/2.0 (spa-link-crawl)"},
            )
        except requests.RequestException:
            continue
        if resp.status_code >= 400:
            continue
        discovered.add(url)
        pages_visited += 1
        # Naive anchor extraction
        for href in re.findall(r'href=["\']([^"\']+)["\']', resp.text or ""):
            absolute = urljoin(url, href)
            if not is_safe_url(absolute) or not absolute.startswith(origin):
                continue
            if absolute in visited:
                continue
            visited.add(absolute)
            queue.append(absolute)
    return discovered


# Late import to avoid the regex module being required at import time
# when the only consumer wants the headless path.
import re  # noqa: E402

__all__ = [
    "DEFAULT_BROWSER_CONCURRENCY",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_PAGES_PER_HOST",
    "DEFAULT_PAGE_TIMEOUT_SECONDS",
    "HAS_PLAYWRIGHT",
    "headless_crawl_host",
    "headless_crawl_hosts",
    "simple_html_link_crawl",
]
