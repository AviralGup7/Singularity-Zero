"""URLScan provider for in-house collectors.

This provider queries urlscan.io's search API for captured pages
related to the provided host.  The implementation is tolerant for
testing: it parses common JSON shapes and falls back to line-oriented
heuristics.

The SSRF / retry boilerplate previously inlined here now lives in
:mod:`src.recon.collectors.http_safety`.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Generator, Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.http_safety import safe_get
from src.recon.collectors.observability import emit_collection_progress
from src.recon.collectors.rate_limiter import acquire as _acquire_token
from src.recon.collectors.types import CollectorMeta, CollectorStatus
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)

URLSCAN_SEARCH = os.environ.get("URLSCAN_SEARCH_URL", "https://urlscan.io/api/v1/search/")

_URL_RE = re.compile(r"https?://[^\s\"\'<>\\)]+", re.IGNORECASE)

# Circuit breaker state
_cb_failures: int = 0
_cb_open_until: float = 0.0
_CB_THRESHOLD = 10  # Open after 10 consecutive failures
_CB_OPEN_SECONDS = 60.0  # Stay open for 60 seconds


def _parse_urlscan_json(text: str, content_type: str = "") -> list[str]:
    urls: list[str] = []
    if content_type and "json" not in content_type and "text" not in content_type:
        logger.warning("urlscan: non-JSON Content-Type: %s", content_type)
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        logger.warning(
            "urlscan: JSON parse error, response text (truncated): %s", (text or "")[:500]
        )
        return []

    if isinstance(data, dict) and "results" in data and isinstance(data["results"], list):
        for item in data["results"]:
            for key in ("page", "task", "result", "url"):
                v = item.get(key) if isinstance(item, dict) else None
                if isinstance(v, dict):
                    url_val = v.get("url")
                    if isinstance(url_val, str):
                        urls.append(url_val)
                        break
                if isinstance(v, str):
                    urls.append(v)
                    break
            item_url = item.get("url") if isinstance(item, dict) else None
            if isinstance(item_url, str):
                urls.append(item_url)
    elif isinstance(data, list):
        for entry in data:
            if isinstance(entry, str):
                urls.append(entry)
            elif isinstance(entry, dict):
                for k in ("page", "task", "url"):
                    v = entry.get(k)
                    if isinstance(v, dict):
                        entry_url = v.get("url")
                        if isinstance(entry_url, str):
                            urls.append(entry_url)
                        break
                    if isinstance(v, str):
                        urls.append(v)
                        break

    return urls


def _collect_for_host(
    host: str,
    timeout_seconds: int,
    per_host_limit: int,
    session: requests.Session | None = None,
) -> set[str]:
    global _cb_failures, _cb_open_until
    if _cb_failures >= _CB_THRESHOLD and time.monotonic() < _cb_open_until:
        return set()

    params = {"q": f"domain:{host}", "size": str(per_host_limit)}
    _acquire_token()
    result = safe_get(
        URLSCAN_SEARCH,
        provider="urlscan",
        timeout_seconds=timeout_seconds,
        params=params,
        session=session,
        max_retries=1,
        ssrf_check_once=True,
    )
    if not result.ok or result.response is None:
        _cb_failures += 1
        if _cb_failures >= _CB_THRESHOLD:
            _cb_open_until = time.monotonic() + _CB_OPEN_SECONDS
        return set()

    content_type = result.response.headers.get("content-type", "")
    candidates = _parse_urlscan_json(result.response.text or "", content_type)
    urls = {normalize_url(u) for u in candidates if normalize_url(u)}
    if urls:
        _cb_failures = 0
    else:
        _cb_failures += 1
        if _cb_failures >= _CB_THRESHOLD:
            _cb_open_until = time.monotonic() + _CB_OPEN_SECONDS
    return urls


def iter_for_hosts(
    hosts: Iterable[str],
    *,
    timeout_seconds: int = 30,
    per_host_limit: int = 100,
    max_workers: int = 6,
    session: requests.Session | None = None,
    progress_callback: Any | None = None,
) -> Generator[tuple[str, set[str], CollectorMeta], None, CollectorMeta]:
    start = time.monotonic()
    hosts_list = [h for h in hosts if h]
    if not hosts_list:
        return CollectorMeta(
            status=CollectorStatus.EMPTY,
            new_urls=0,
            hosts_scanned=0,
            provider_name="urlscan",
        )

    workers = min(max_workers, max(1, len(hosts_list)))
    errors = 0
    timeout_count = 0
    total_new = 0

    emit_collection_progress(progress_callback, f"URLScan: scanning {len(hosts_list)} hosts", 10)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_host = {
            executor.submit(_collect_for_host, host, timeout_seconds, per_host_limit, session): host
            for host in hosts_list
        }
        idx = 0
        for future in future_to_host:
            idx += 1
            host = future_to_host[future]
            try:
                host_urls = future.result()
            except requests.Timeout as exc:
                host_urls = set()
                errors += 1
                timeout_count += 1
                collector_metrics.increment_errors("urlscan")
                logger.debug("URLScan timeout for %s: %s", host, exc)
            except Exception as exc:
                host_urls = set()
                errors += 1
                collector_metrics.increment_errors("urlscan")
                logger.debug("URLScan host future failed for %s: %s", host, exc)

            host_meta = CollectorMeta(
                status=CollectorStatus.OK if host_urls else CollectorStatus.EMPTY,
                new_urls=len(host_urls),
                hosts_scanned=1,
                provider_name="urlscan",
                extras={"host": host},
            )
            total_new += len(host_urls)
            if host_urls:
                collector_metrics.increment_urls("urlscan", len(host_urls))
            emit_collection_progress(
                progress_callback,
                f"URLScan host {idx}/{len(hosts_list)}: +{len(host_urls)} urls, total {total_new}",
                10 + int((idx / len(hosts_list)) * 40),
                processed=idx,
                total=len(hosts_list),
            )
            yield host, host_urls, host_meta

    duration = round(time.monotonic() - start, 1)
    collector_metrics.observe_duration("urlscan", duration)
    return CollectorMeta(
        status=CollectorStatus.OK if total_new else CollectorStatus.EMPTY,
        duration_seconds=duration,
        new_urls=total_new,
        errors=errors,
        timeout_count=timeout_count,
        hosts_scanned=len(hosts_list),
        provider_name="urlscan",
    )


def collect_for_hosts(
    hosts: Iterable[str],
    timeout_seconds: int = 30,
    per_host_limit: int = 100,
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


__all__ = ["collect_for_hosts", "iter_for_hosts", "URLSCAN_SEARCH"]
