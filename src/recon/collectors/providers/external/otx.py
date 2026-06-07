"""AlienVault OTX provider for in-house collectors.

Fetches URL lists associated with a domain via OTX.  If an API key is
required or the service returns unexpected shapes, the provider is
forgiving and returns an empty set.

The SSRF / retry boilerplate previously inlined here now lives in
:mod:`src.recon.collectors.http_safety`.
"""

from __future__ import annotations

import json
import logging
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

OTX_DOMAIN_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"


def _parse_otx_json(text: str) -> list[str]:
    urls: list[str] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("otx: JSON parse error, response text (truncated): %s", (text or "")[:500])
        return [line.strip() for line in (text or "").splitlines() if line.strip()]

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
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                url_val = item.get("url")
                if isinstance(url_val, str):
                    urls.append(url_val)
            elif isinstance(item, str):
                urls.append(item)

    return urls


def _collect_for_host(
    host: str,
    timeout_seconds: int,
    per_host_limit: int,
    session: requests.Session | None = None,
) -> set[str]:
    """OTX is rate-limited and does not paginate cleanly; one call per host."""
    url = OTX_DOMAIN_URL.format(domain=host)
    _acquire_token()
    result = safe_get(
        url,
        provider="otx",
        timeout_seconds=timeout_seconds,
        headers={"User-Agent": "target-specific-pipeline/2.0"},
        session=session,
        max_retries=1,
        ssrf_check_once=False,  # url contains host-specific path so cache-once does not apply
    )
    if not result.ok or result.response is None:
        return set()

    candidates = _parse_otx_json(result.response.text or "")
    return {normalize_url(u) for u in candidates if normalize_url(u)}


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
            provider_name="otx",
        )

    workers = min(max_workers, max(1, len(hosts_list)))
    errors = 0
    timeout_count = 0
    total_new = 0

    emit_collection_progress(progress_callback, f"OTX: scanning {len(hosts_list)} hosts", 10)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_host = {
            executor.submit(
                _collect_for_host, host, timeout_seconds, per_host_limit, session
            ): host
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
                collector_metrics.increment_errors("otx")
                logger.debug("OTX timeout for %s: %s", host, exc)
            except Exception as exc:
                host_urls = set()
                errors += 1
                collector_metrics.increment_errors("otx")
                logger.debug("OTX host future failed for %s: %s", host, exc)

            host_meta = CollectorMeta(
                status=CollectorStatus.OK if host_urls else CollectorStatus.EMPTY,
                new_urls=len(host_urls),
                hosts_scanned=1,
                provider_name="otx",
                extras={"host": host},
            )
            total_new += len(host_urls)
            if host_urls:
                collector_metrics.increment_urls("otx", len(host_urls))
            emit_collection_progress(
                progress_callback,
                f"OTX host {idx}/{len(hosts_list)}: +{len(host_urls)} urls, total {total_new}",
                10 + int((idx / len(hosts_list)) * 40),
                processed=idx,
                total=len(hosts_list),
            )
            yield host, host_urls, host_meta

    duration = round(time.monotonic() - start, 1)
    collector_metrics.observe_duration("otx", duration)
    return CollectorMeta(
        status=CollectorStatus.OK if total_new else CollectorStatus.EMPTY,
        duration_seconds=duration,
        new_urls=total_new,
        errors=errors,
        timeout_count=timeout_count,
        hosts_scanned=len(hosts_list),
        provider_name="otx",
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


__all__ = ["collect_for_hosts", "iter_for_hosts", "OTX_DOMAIN_URL"]
