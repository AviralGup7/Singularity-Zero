"""CommonCrawl provider for in-house URL collection.

This provider queries the CommonCrawl index endpoints and extracts
original URLs. The implementation is conservative and test-friendly:
it tolerates NDJSON, JSON arrays, and plain-line responses.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.observability import emit_collection_progress
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)

# Base endpoint template; the exact index name is not important for tests
CC_INDEX_BASE = "https://index.commoncrawl.org/CC-MAIN-2023-14-index"


def _parse_cc_ndjson(text: str) -> list[str]:
    urls: list[str] = []
    # Try NDJSON or line-based JSON objects
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            # not JSON, treat the line as a URL
            urls.append(line)
            continue

        if isinstance(obj, dict):
            # CommonCrawl records often contain 'url' or 'original'
            for key in ("url", "original", "loc"):
                if key in obj and isinstance(obj[key], str):
                    urls.append(obj[key])
                    break
        elif isinstance(obj, list) and obj:
            # fallback to first element
            first = obj[0]
            if isinstance(first, str):
                urls.append(first)

    return urls


def _collect_for_host(host: str, timeout_seconds: int, per_host_limit: int) -> set[str]:
    params = {
        "url": f"{host}/*",
        "output": "json",
        "limit": str(per_host_limit),
    }
    try:
        collector_metrics.increment_requests("commoncrawl")
        resp = requests.get(CC_INDEX_BASE, params=params, timeout=max(2, timeout_seconds))
    except requests.RequestException as exc:  # pragma: no cover - network
        logger.debug("CommonCrawl request failed for %s: %s", host, exc)
        collector_metrics.increment_errors("commoncrawl")
        return set()

    if resp.status_code >= 400:
        logger.debug("CommonCrawl returned status %s for %s", resp.status_code, host)
        collector_metrics.increment_errors("commoncrawl")
        return set()

    candidates = _parse_cc_ndjson(resp.text or "")
    normalized = {normalize_url(u) for u in candidates if normalize_url(u)}
    return normalized


def collect_for_hosts(
    hosts: Iterable[str],
    timeout_seconds: int = 30,
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
    workers = min(max_workers, max(1, len(hosts_list)))

    emit_collection_progress(
        progress_callback,
        f"CommonCrawl: scanning {len(hosts_list)} hosts",
        10,
    )

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_collect_for_host, host, timeout_seconds, per_host_limit)
            for host in hosts_list
        ]
        for idx, future in enumerate(futures, start=1):
            try:
                host_urls = future.result()
            except Exception:
                host_urls = set()
                errors += 1
                collector_metrics.increment_errors("commoncrawl")
            before = len(discovered)
            discovered.update(host_urls)
            delta = len(discovered) - before
            if delta > 0:
                collector_metrics.increment_urls("commoncrawl", delta)
            emit_collection_progress(
                progress_callback,
                f"CommonCrawl host {idx}/{len(hosts_list)}: +{len(discovered) - before} urls, total {len(discovered)}",
                10 + int((idx / len(hosts_list)) * 40),
                processed=idx,
                total=len(hosts_list),
            )

    duration = round(time.monotonic() - start, 1)
    collector_metrics.observe_duration("commoncrawl", duration)
    meta = {
        "status": "ok" if discovered else "empty",
        "duration_seconds": duration,
        "new_urls": len(discovered),
        "hosts_scanned": len(hosts_list),
        "errors": errors,
    }
    return discovered, meta
