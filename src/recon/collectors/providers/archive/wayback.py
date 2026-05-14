"""Minimal Wayback CDX provider used by the in-house collector.

This module implements a small client that queries the Wayback CDX
endpoint for a list of captured originals for a host. The goal is to
provide a simple, testable replacement for archive-based URL collection
without copying external CLI code.
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

CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
DEFAULT_MAX_RETRIES = 2
DEFAULT_BACKOFF_SECONDS = 0.5


def _parse_cdx_json(text: str) -> list[str]:
    """Parse typical Wayback CDX JSON output into a list of original URLs.

    The CDX "output=json" format commonly returns an array of arrays; the
    first row may be field names. This parser tries to handle the common
    shapes and falls back to line-oriented heuristics.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # fallback: lines where each line is a URL
        return [line.strip() for line in text.splitlines() if line.strip()]

    if not isinstance(data, list):
        return []

    # If the first row looks like a header row (contains 'original'), skip it
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


def _collect_for_host(host: str, timeout_seconds: int, per_host_limit: int) -> set[str]:
    params = {
        "url": f"{host}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(per_host_limit),
    }
    # Simple retry loop for transient network errors. Keeps behavior
    # conservative: on repeated failure return empty set.
    attempts = 1 + DEFAULT_MAX_RETRIES
    backoff = DEFAULT_BACKOFF_SECONDS
    resp = None
    for attempt in range(1, attempts + 1):
        collector_metrics.increment_requests("wayback")
        try:
            resp = requests.get(CDX_ENDPOINT, params=params, timeout=max(2, timeout_seconds))
            break
        except requests.RequestException as exc:  # pragma: no cover - network
            logger.debug(
                "Wayback request failed for %s (attempt %d/%d): %s", host, attempt, attempts, exc
            )
            collector_metrics.increment_errors("wayback")
            if attempt < attempts:
                try:
                    time.sleep(backoff * (2 ** (attempt - 1)))
                except Exception as e:
                    logger.debug("sleep interrupted during wayback retry for %s: %s", host, e)
            else:
                return set()

    originals = _parse_cdx_json(resp.text or "")
    normalized = {normalize_url(u) for u in originals if normalize_url(u)}
    return normalized


def collect_for_hosts(
    hosts: Iterable[str],
    timeout_seconds: int = 30,
    per_host_limit: int = 1000,
    max_workers: int = 6,
    progress_callback: Any | None = None,
) -> tuple[set[str], dict[str, Any]]:
    """Collect original URLs for a set of hosts from Wayback.

    Returns a tuple of (urls_set, meta) where meta contains status, duration,
    and counts. The function is conservative and returns an empty set on
    network failures.
    """
    start = time.monotonic()
    hosts_list = [h for h in hosts if h]
    if not hosts_list:
        return set(), {"status": "empty", "duration_seconds": 0.0, "new_urls": 0}

    discovered: set[str] = set()
    errors = 0
    workers = min(max_workers, max(1, len(hosts_list)))

    emit_collection_progress(
        progress_callback,
        f"Wayback: scanning {len(hosts_list)} hosts",
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
            except Exception as e:
                host_urls = set()
                errors += 1
                collector_metrics.increment_errors("wayback")
                logger.debug("Wayback host future failed for index %d: %s", idx, e)
            before = len(discovered)
            discovered.update(host_urls)
            # emit metrics for newly discovered URLs from this provider
            delta = len(discovered) - before
            if delta > 0:
                collector_metrics.increment_urls("wayback", delta)
            emit_collection_progress(
                progress_callback,
                f"Wayback host {idx}/{len(hosts_list)}: +{len(discovered) - before} urls, total {len(discovered)}",
                10 + int((idx / len(hosts_list)) * 40),
                processed=idx,
                total=len(hosts_list),
            )

    duration = round(time.monotonic() - start, 1)
    collector_metrics.observe_duration("wayback", duration)
    meta = {
        "status": "ok" if discovered else "empty",
        "duration_seconds": duration,
        "new_urls": len(discovered),
        "hosts_scanned": len(hosts_list),
        "errors": errors,
    }
    return discovered, meta
