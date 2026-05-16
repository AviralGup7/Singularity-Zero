"""AlienVault OTX provider for in-house collectors.

Fetches URL lists associated with a domain via OTX. If an API key is
required or the service returns unexpected shapes, the provider is
forgiving and returns an empty set.
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

OTX_DOMAIN_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"


def _parse_otx_json(text: str) -> list[str]:
    urls: list[str] = []
    try:
        data = json.loads(text)
    except Exception:
        return [line.strip() for line in (text or "").splitlines() if line.strip()]

    # OTX may return an object with 'url_list' or 'results'
    if isinstance(data, dict):
        for key in ("url_list", "results", "data"):
            arr = data.get(key)
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict):
                        url_val = item.get("url")
                        if isinstance(url_val, str):
                            urls.append(url_val)
                    elif isinstance(item, str):
                        urls.append(item)
                if urls:
                    return urls
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                url_val = item.get("url")
                if isinstance(url_val, str):
                    urls.append(url_val)
            elif isinstance(item, str):
                urls.append(item)

    return urls


def _collect_for_host(host: str, timeout_seconds: int, per_host_limit: int) -> set[str]:
    url = OTX_DOMAIN_URL.format(domain=host)
    headers = {"User-Agent": "target-specific-pipeline/2.0"}
    # OTX requires API key for some endpoints; if not available, return empty set
    # but still attempt the request for permissive endpoints.
    attempts = 2
    resp = None
    for attempt in range(1, attempts + 1):
        collector_metrics.increment_requests("otx")
        try:
            _acquire_token()
            resp = requests.get(url, headers=headers, timeout=max(2, timeout_seconds))
            break
        except requests.RequestException as exc:
            collector_metrics.increment_errors("otx")
            logger.debug(
                "OTX request failed for %s (attempt %d/%d): %s", host, attempt, attempts, exc
            )
            if attempt < attempts:
                time.sleep(0.25 * attempt)
            else:
                return set()

    if resp is None or resp.status_code >= 400:
        return set()

    candidates = _parse_otx_json(resp.text or "")
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

    emit_collection_progress(progress_callback, f"OTX: scanning {len(hosts_list)} hosts", 10)

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
                collector_metrics.increment_errors("otx")
            before = len(discovered)
            discovered.update(host_urls)
            delta = len(discovered) - before
            if delta > 0:
                collector_metrics.increment_urls("otx", delta)
            emit_collection_progress(
                progress_callback,
                f"OTX host {idx}/{len(hosts_list)}: +{delta} urls, total {len(discovered)}",
                10 + int((idx / len(hosts_list)) * 40),
                processed=idx,
                total=len(hosts_list),
            )

    duration = round(time.monotonic() - start, 1)
    collector_metrics.observe_duration("otx", duration)
    meta = {
        "status": "ok" if discovered else "empty",
        "duration_seconds": duration,
        "new_urls": len(discovered),
        "hosts_scanned": len(hosts_list),
        "errors": errors,
    }
    return discovered, meta


__all__ = ["collect_for_hosts"]
