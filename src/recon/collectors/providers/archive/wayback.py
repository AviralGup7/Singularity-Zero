"""Minimal Wayback CDX provider used by the in-house collector.

This module implements a small client that queries the Wayback CDX
endpoint for a list of captured originals for a host.  The goal is to
provide a simple, testable replacement for archive-based URL collection
without copying external CLI code.

This file used to inline ~80 lines of SSRF / retry / DNS-caching
logic; that boilerplate now lives in
:mod:`src.recon.collectors.http_safety` and the surface area here is
the parsing + result aggregation that is genuinely Wayback-specific.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Generator, Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.http_safety import safe_get
from src.recon.collectors.observability import emit_collection_progress
from src.recon.collectors.types import CollectorMeta, CollectorStatus
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)

CDX_ENDPOINT = os.environ.get("WAYBACK_CDX_ENDPOINT", "https://web.archive.org/cdx/search/cdx")
DEFAULT_MAX_RETRIES = 2
DEFAULT_BACKOFF_SECONDS = 0.5

# Circuit breaker state
_cb_failures: int = 0
_cb_open_until: float = 0.0
_CB_THRESHOLD = 10  # Open after 10 consecutive failures
_CB_OPEN_SECONDS = 60.0  # Stay open for 60 seconds


def _parse_cdx_json(text: str) -> list[str]:
    """Parse typical Wayback CDX JSON output into a list of original URLs.

    The CDX ``output=json`` format commonly returns an array of arrays;
    the first row may be field names.  This parser tries to handle the
    common shapes and falls back to line-oriented heuristics.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        logger.warning(
            "wayback: JSON parse error, response text (truncated): %s", (text or "")[:500]
        )
        return [line.strip() for line in text.splitlines() if line.strip()]

    if not isinstance(data, list):
        return []

    rows = (
        data[1:]
        if data
        and isinstance(data[0], list)
        and any(isinstance(cell, str) and cell.lower().strip() == "original" for cell in data[0])
        else data
    )

    originals: list[str] = []
    for row in rows:
        if isinstance(row, list) and row:
            originals.append(row[0])
        elif isinstance(row, str):
            originals.append(row)
    return originals


def _collect_for_host(
    host: str,
    timeout_seconds: int,
    per_host_limit: int,
    session: requests.Session | None = None,
) -> set[str]:
    """Single-host CDX lookup.  Network failures return an empty set."""
    global _cb_failures, _cb_open_until
    if _cb_failures >= _CB_THRESHOLD and time.monotonic() < _cb_open_until:
        return set()

    params = {
        "url": f"{host}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(per_host_limit),
    }

    result = safe_get(
        CDX_ENDPOINT,
        provider="wayback",
        timeout_seconds=timeout_seconds,
        params=params,
        session=session,
        max_retries=DEFAULT_MAX_RETRIES,
        backoff_seconds=DEFAULT_BACKOFF_SECONDS,
        ssrf_check_once=True,
    )
    if not result.ok or result.response is None:
        _cb_failures += 1
        if _cb_failures >= _CB_THRESHOLD:
            _cb_open_until = time.monotonic() + _CB_OPEN_SECONDS
        return set()

    originals = _parse_cdx_json(result.response.text or "")
    normalized = {normalize_url(u) for u in originals if normalize_url(u)}
    if normalized:
        _cb_failures = 0
    else:
        _cb_failures += 1
        if _cb_failures >= _CB_THRESHOLD:
            _cb_open_until = time.monotonic() + _CB_OPEN_SECONDS
    return normalized


def iter_for_hosts(
    hosts: Iterable[str],
    *,
    timeout_seconds: int = 30,
    per_host_limit: int = 1000,
    max_workers: int = 6,
    session: requests.Session | None = None,
    progress_callback: Any | None = None,
) -> Generator[tuple[str, set[str], CollectorMeta], None, CollectorMeta]:
    """Yield per-host ``(host, urls, host_meta)`` triples as each host completes.

    This is the generator counterpart to :func:`collect_for_hosts`.
    Yielding incrementally lets the streaming aggregator emit URLs as
    soon as the first host completes, instead of waiting for every host
    to finish.

    Returns the aggregate :class:`CollectorMeta` for the run via
    ``StopIteration.value`` when the generator is exhausted.
    """
    start = time.monotonic()
    hosts_list = [h for h in hosts if h]
    if not hosts_list:
        empty = CollectorMeta(
            status=CollectorStatus.EMPTY,
            duration_seconds=0.0,
            new_urls=0,
            hosts_scanned=0,
            provider_name="wayback",
        )
        return empty

    workers = min(max_workers, max(1, len(hosts_list)))
    errors = 0
    timeout_count = 0
    total_new = 0

    emit_collection_progress(
        progress_callback,
        f"Wayback: scanning {len(hosts_list)} hosts",
        10,
    )

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
                collector_metrics.increment_errors("wayback")
                logger.debug("Wayback timeout for %s: %s", host, exc)
            except Exception as exc:
                host_urls = set()
                errors += 1
                collector_metrics.increment_errors("wayback")
                logger.debug("Wayback host future failed for %s: %s", host, exc)

            host_meta = CollectorMeta(
                status=CollectorStatus.OK if host_urls else CollectorStatus.EMPTY,
                duration_seconds=0.0,
                new_urls=len(host_urls),
                hosts_scanned=1,
                provider_name="wayback",
                extras={"host": host},
            )
            total_new += len(host_urls)
            if host_urls:
                collector_metrics.increment_urls("wayback", len(host_urls))
            emit_collection_progress(
                progress_callback,
                f"Wayback host {idx}/{len(hosts_list)}: +{len(host_urls)} urls, "
                f"running total {total_new}",
                10 + int((idx / len(hosts_list)) * 40),
                processed=idx,
                total=len(hosts_list),
            )
            yield host, host_urls, host_meta

    duration = round(time.monotonic() - start, 1)
    collector_metrics.observe_duration("wayback", duration)
    return CollectorMeta(
        status=CollectorStatus.OK if total_new else CollectorStatus.EMPTY,
        duration_seconds=duration,
        new_urls=total_new,
        errors=errors,
        timeout_count=timeout_count,
        hosts_scanned=len(hosts_list),
        provider_name="wayback",
    )


def collect_for_hosts(
    hosts: Iterable[str],
    timeout_seconds: int = 30,
    per_host_limit: int = 1000,
    max_workers: int = 6,
    progress_callback: Any | None = None,
    *,
    session: requests.Session | None = None,
) -> tuple[set[str], CollectorMeta]:
    """Collect original URLs for a set of hosts from Wayback.

    Returns a tuple of (urls_set, meta) where meta is a
    :class:`CollectorMeta` (dict-compatible).  The function is
    conservative and returns an empty set on network failures.

    The ``session`` keyword is optional: when omitted, the call path
    falls back to ``requests.get`` so existing tests that
    monkey-patch ``requests.get`` continue to work.  Pass a shared
    :func:`src.recon.collectors.http_safety.get_default_session`
    instance in production to benefit from HTTP connection pooling.
    """
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

    # Replace the inner ``new_urls`` (sum of per-host counts) with the
    # deduplicated total so downstream consumers see the same value
    # they would by calling ``len(discovered)``.
    aggregate_meta = aggregate_meta.with_updates(new_urls=len(discovered))
    return discovered, aggregate_meta


__all__ = ["collect_for_hosts", "iter_for_hosts", "CDX_ENDPOINT"]
