"""URLScan provider for in-house collectors.

This provider queries urlscan.io's search API for captured pages related
to the provided host. The implementation is tolerant for testing: it
parses common JSON shapes and falls back to line-oriented heuristics.
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
from src.recon.collectors.rate_limiter import acquire as _acquire_token
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)

URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"


def _parse_urlscan_json(text: str) -> list[str]:
    urls: list[str] = []
    try:
        data = json.loads(text)
    except Exception:
        # fallback: treat each non-empty line as a URL
        return [line.strip() for line in (text or "").splitlines() if line.strip()]

    # urlscan search returns an object with 'results' array
    if isinstance(data, dict) and "results" in data and isinstance(data["results"], list):
        for item in data["results"]:
            # url may appear in several locations
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
            # direct url field
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


def _collect_for_host(host: str, timeout_seconds: int, per_host_limit: int) -> set[str]:
    params = {"q": f"domain:{host}", "size": str(per_host_limit)}
    attempts = 2
    resp = None
    for attempt in range(1, attempts + 1):
        collector_metrics.increment_requests("urlscan")
        try:
            _acquire_token()
            resp = requests.get(URLSCAN_SEARCH, params=params, timeout=max(2, timeout_seconds))
            break
        except requests.RequestException as exc:
            collector_metrics.increment_errors("urlscan")
            logger.debug(
                "urlscan request failed for %s (attempt %d/%d): %s", host, attempt, attempts, exc
            )
            if attempt < attempts:
                time.sleep(0.25 * attempt)
            else:
                return set()

    if resp is None or resp.status_code >= 400:
        return set()

    candidates = _parse_urlscan_json(resp.text or "")
    normalized = {normalize_url(u) for u in candidates if normalize_url(u)}
    return normalized


def collect_for_hosts(
    hosts: Iterable[str],
    timeout_seconds: int = 30,
    per_host_limit: int = 100,
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

    emit_collection_progress(progress_callback, f"URLScan: scanning {len(hosts_list)} hosts", 10)

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
                collector_metrics.increment_errors("urlscan")
            before = len(discovered)
            discovered.update(host_urls)
            delta = len(discovered) - before
            if delta > 0:
                collector_metrics.increment_urls("urlscan", delta)
            emit_collection_progress(
                progress_callback,
                f"URLScan host {idx}/{len(hosts_list)}: +{delta} urls, total {len(discovered)}",
                10 + int((idx / len(hosts_list)) * 40),
                processed=idx,
                total=len(hosts_list),
            )

    duration = round(time.monotonic() - start, 1)
    collector_metrics.observe_duration("urlscan", duration)
    meta = {
        "status": "ok" if discovered else "empty",
        "duration_seconds": duration,
        "new_urls": len(discovered),
        "hosts_scanned": len(hosts_list),
        "errors": errors,
    }
    return discovered, meta


__all__ = ["collect_for_hosts"]
