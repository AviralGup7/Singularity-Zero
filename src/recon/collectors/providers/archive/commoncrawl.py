"""CommonCrawl provider for in-house URL collection.

This provider queries the CommonCrawl index endpoints and extracts
original URLs.  The implementation is conservative and test-friendly:
it tolerates NDJSON, JSON arrays, and plain-line responses.

The previous version hard-coded ``COMMONCRAWL_INDEX_BASE`` to
``CC-MAIN-2023-14-index`` (a February 2023 snapshot), silently missing
every crawl since.  The provider now calls the
``https://index.commoncrawl.org/collinfo.json`` discovery endpoint at
startup, caches the most recent N indexes, and round-robins across
them so a single busy snapshot does not rate-limit the entire scan.

The SSRF / retry / connection-pooling boilerplate previously inlined in
this module now lives in :mod:`src.recon.collectors.http_safety`.
"""

from __future__ import annotations

import json
import logging
import threading
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

# Fallback index for offline / air-gapped environments and unit tests.
# Production traffic should always go through the dynamic discovery path
# (see ``_discover_indexes`` below).
COMMONCRAWL_INDEX_BASE = "https://index.commoncrawl.org/CC-MAIN-2023-14-index"

# Discovery endpoint that lists every available crawl index.
COMMONCRAWL_COLLINFO = "https://index.commoncrawl.org/collinfo.json"

# How many of the most recent indexes to round-robin across.
_DEFAULT_RECENT_INDEXES = 5

# How long (seconds) the discovered-index list is cached for.
_INDEX_CACHE_TTL_SECONDS = 12 * 60 * 60


# ---------------------------------------------------------------------------
# Dynamic index discovery
# ---------------------------------------------------------------------------

_DISCOVERED_INDEXES: list[str] = []
_DISCOVERED_INDEXES_LOCK = threading.Lock()
_DISCOVERED_INDEXES_FETCHED_AT: float = 0.0
_DISCOVERED_INDEXES_ROUND_ROBIN = 0


def _resolve_recent_index_count() -> int:
    """Read the configured number of recent indexes (env > default)."""
    import os

    raw = os.environ.get("COMMONCRAWL_RECENT_INDEXES")
    if raw:
        try:
            n = int(raw)
            if n > 0:
                return n
        except ValueError as exc:
            logger.warning("Operation failed in commoncrawl.py: %s", exc, exc_info=True)  # noqa: BLE001
    return _DEFAULT_RECENT_INDEXES


def _discover_indexes(*, timeout_seconds: int = 10) -> list[str]:
    """Call the collinfo endpoint and return the *N* most recent indexes."""
    result = safe_get(
        COMMONCRAWL_COLLINFO,
        provider="commoncrawl",
        timeout_seconds=timeout_seconds,
        max_retries=1,
        ssrf_check_once=True,
    )
    if not result.ok or result.response is None:
        return []

    # We accept any of (a) a real ``resp.json()``, (b) a response that
    # only exposes ``.text`` (the test mocks do this), and (c) a
    # response that exposes ``.json`` as an attribute set to a list.
    data: Any = None
    try:
        json_attr = getattr(result.response, "json", None)
        if callable(json_attr):
            data = json_attr()
        elif json_attr is not None:
            data = json_attr
        else:
            data = json.loads(getattr(result.response, "text", "") or "")
    except (json.JSONDecodeError, ValueError, AttributeError, TypeError) as exc:
        logger.debug("CommonCrawl collinfo discovery failed: %s", exc)
        return []

    if not isinstance(data, list):
        return []

    ids: list[str] = []
    for entry in data:
        if isinstance(entry, dict):
            index_id = entry.get("id") or entry.get("name")
            if isinstance(index_id, str) and index_id:
                ids.append(index_id)
        elif isinstance(entry, str) and entry:
            ids.append(entry)

    ids.sort(reverse=True)
    return ids[: _resolve_recent_index_count()]


def _get_recent_indexes() -> list[str]:
    """Return the cached recent-index list, refreshing it when stale."""
    global _DISCOVERED_INDEXES, _DISCOVERED_INDEXES_FETCHED_AT
    now = time.monotonic()
    with _DISCOVERED_INDEXES_LOCK:
        if (
            not _DISCOVERED_INDEXES
            or now - _DISCOVERED_INDEXES_FETCHED_AT > _INDEX_CACHE_TTL_SECONDS
        ):
            fresh = _discover_indexes()
            if fresh:
                _DISCOVERED_INDEXES = fresh
                _DISCOVERED_INDEXES_FETCHED_AT = now
                logger.info(
                    "CommonCrawl: discovered %d recent indexes (top=%s)",
                    len(fresh),
                    fresh[0] if fresh else "<none>",
                )
    return list(_DISCOVERED_INDEXES)


def _next_index_for_request() -> str:
    """Return the next index to query, round-robin across discovered indexes."""
    global _DISCOVERED_INDEXES_ROUND_ROBIN
    indexes = _get_recent_indexes()
    if not indexes:
        return COMMONCRAWL_INDEX_BASE
    with _DISCOVERED_INDEXES_LOCK:
        idx = indexes[_DISCOVERED_INDEXES_ROUND_ROBIN % len(indexes)]
        _DISCOVERED_INDEXES_ROUND_ROBIN += 1
    return f"https://index.commoncrawl.org/{idx}-index"


def force_refresh_indexes() -> list[str]:
    """Invalidate the cache and re-discover.  Useful for tests."""
    global _DISCOVERED_INDEXES, _DISCOVERED_INDEXES_FETCHED_AT
    with _DISCOVERED_INDEXES_LOCK:
        _DISCOVERED_INDEXES = []
        _DISCOVERED_INDEXES_FETCHED_AT = 0.0
    return _get_recent_indexes()


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def _parse_cc_ndjson(text: str) -> list[str]:
    urls: list[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("commoncrawl: JSON parse error, line (truncated): %s", line[:500])
            urls.append(line)
            continue

        if isinstance(obj, dict):
            for key in ("url", "original", "loc"):
                if key in obj and isinstance(obj[key], str):
                    urls.append(obj[key])
                    break
        elif isinstance(obj, list) and obj:
            first = obj[0]
            if isinstance(first, str):
                urls.append(first)

    return urls


def _collect_for_host(
    host: str,
    timeout_seconds: int,
    per_host_limit: int,
    session: requests.Session | None = None,
) -> set[str]:
    """Query a single host against the next round-robin CommonCrawl index."""
    index_url = _next_index_for_request()
    params = {
        "url": f"{host}/*",
        "output": "json",
        "limit": str(per_host_limit),
    }
    result = safe_get(
        index_url,
        provider="commoncrawl",
        timeout_seconds=timeout_seconds,
        params=params,
        session=session,
        max_retries=1,
        ssrf_check_once=True,
    )
    if not result.ok or result.response is None:
        return set()

    candidates = _parse_cc_ndjson(result.response.text or "")
    return {normalize_url(u) for u in candidates if normalize_url(u)}


# ---------------------------------------------------------------------------
# Streaming + aggregate APIs
# ---------------------------------------------------------------------------


def iter_for_hosts(
    hosts: Iterable[str],
    *,
    timeout_seconds: int = 30,
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
            duration_seconds=0.0,
            new_urls=0,
            hosts_scanned=0,
            provider_name="commoncrawl",
        )

    workers = min(max_workers, max(1, len(hosts_list)))
    errors = 0
    timeout_count = 0
    total_new = 0

    emit_collection_progress(
        progress_callback,
        f"CommonCrawl: scanning {len(hosts_list)} hosts",
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
                collector_metrics.increment_errors("commoncrawl")
                logger.debug("CommonCrawl timeout for %s: %s", host, exc)
            except Exception as exc:
                host_urls = set()
                errors += 1
                collector_metrics.increment_errors("commoncrawl")
                logger.debug("CommonCrawl host future failed for %s: %s", host, exc)

            host_meta = CollectorMeta(
                status=CollectorStatus.OK if host_urls else CollectorStatus.EMPTY,
                new_urls=len(host_urls),
                hosts_scanned=1,
                provider_name="commoncrawl",
                extras={"host": host},
            )
            total_new += len(host_urls)
            if host_urls:
                collector_metrics.increment_urls("commoncrawl", len(host_urls))
            emit_collection_progress(
                progress_callback,
                f"CommonCrawl host {idx}/{len(hosts_list)}: +{len(host_urls)} urls, "
                f"running total {total_new}",
                10 + int((idx / len(hosts_list)) * 40),
                processed=idx,
                total=len(hosts_list),
            )
            yield host, host_urls, host_meta

    duration = round(time.monotonic() - start, 1)
    collector_metrics.observe_duration("commoncrawl", duration)
    return CollectorMeta(
        status=CollectorStatus.OK if total_new else CollectorStatus.EMPTY,
        duration_seconds=duration,
        new_urls=total_new,
        errors=errors,
        timeout_count=timeout_count,
        hosts_scanned=len(hosts_list),
        provider_name="commoncrawl",
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
    """Collect original URLs for a set of hosts from CommonCrawl."""
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


__all__ = [
    "collect_for_hosts",
    "iter_for_hosts",
    "force_refresh_indexes",
    "COMMONCRAWL_INDEX_BASE",
    "COMMONCRAWL_COLLINFO",
]
