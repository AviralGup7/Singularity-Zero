
"""Fallback / urllib3-based probing and health checks.

Extracted from ``src.recon.live_hosts``.  Provides the urllib3-backed probing
path that is used when httpx is unavailable or the scan mode is ``safe``.
"""

from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import urllib3

from src.core.models import DEFAULT_USER_AGENT, Config
from src.core.utils.http_pool import get_pooled_connection
from src.core.utils.url_validation import is_safe_url
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)


def probe_live_hosts_fallback(
    subdomains: set[str],
    timeout_seconds: int,
    config: Config | None = None,
    progress_callback: Any = None,
    *,
    force_recheck: bool = False,
) -> tuple[list[dict[str, Any]], set[str]]:
    from src.recon.live_hosts.discovery import (
        PROBE_CACHE_DEFAULT_TTL_SECONDS,
        _cache_lookup,
        _cache_update_from_batch,
        _normalized_probe_hosts,
        _probe_cache_ttl_seconds,
        emit_collection_progress,
    )

    hosts = _normalized_probe_hosts(subdomains)
    if not hosts:
        return [], set()

    emit_collection_progress(
        progress_callback,
        f"live-host preparing {len(hosts)} host candidates",
        36,
        processed=0,
        total=len(hosts),
        stage_percent=0,
    )

    target_name = getattr(config, "target_name", "") if config else ""
    ttl_seconds = _probe_cache_ttl_seconds(config) if config else PROBE_CACHE_DEFAULT_TTL_SECONDS
    to_probe, records, live_hosts, skipped_count = _cache_lookup(
        hosts, ttl_seconds, force_recheck, target_name=target_name
    )
    if skipped_count:
        emit_collection_progress(
            progress_callback,
            f"live-host cache hit: skipped {skipped_count}/{len(hosts)} hosts",
            36,
            processed=skipped_count,
            total=len(hosts),
            stage_percent=int((skipped_count / max(1, len(hosts))) * 100),
        )

    if not to_probe:
        if force_recheck:
            return records, live_hosts
        if hosts and not live_hosts:
            emit_collection_progress(
                progress_callback,
                "live-host cache contains no alive entries; forcing one fresh probe pass",
                36,
                processed=skipped_count,
                total=len(hosts),
                stage_percent=100,
            )
            return probe_live_hosts_fallback(
                subdomains,
                timeout_seconds,
                config=config,
                progress_callback=progress_callback,
                force_recheck=True,
            )
        return records, live_hosts

    workers = max(16, min(128, int(config.httpx.get("fallback_threads", 48) if config else 48)))
    batch_size = min(max(workers, 24), max(24, len(to_probe) // 8 or 24))
    total_batches = max(1, (len(to_probe) + batch_size - 1) // batch_size)
    executor_workers = min(workers, len(to_probe))
    emit_collection_progress(
        progress_callback,
        f"live-host fallback probing started: {len(to_probe)} hosts queued across "
        f"{total_batches} batch(es) with concurrency {executor_workers}",
        37,
        processed=skipped_count,
        total=len(hosts),
        stage_percent=int((skipped_count / max(1, len(hosts))) * 100),
        queued_hosts=len(to_probe),
        total_batches=total_batches,
        batch_size=batch_size,
        concurrency=executor_workers,
    )

    with ThreadPoolExecutor(max_workers=executor_workers) as executor:
        future_to_host = {
            executor.submit(probe_host_without_httpx, host, timeout_seconds): host
            for host in to_probe
        }
        processed = 0
        current_batch = 0
        batch_hosts: list[str] = []
        batch_records: list[dict[str, Any]] = []
        batch_live: set[str] = set()
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            processed += 1
            batch_hosts.append(host)
            try:
                result = future.result()
            except Exception as exc:
                logger.warning("Error during host probing for %s: %s", host, exc)
                result = None
            if result and result.get("url"):
                observed_url = str(result.get("url", "") or "").strip()
                if observed_url:
                    live_hosts.add(observed_url)
                    batch_live.add(observed_url)
                records.append(result)
                batch_records.append(result)
            if len(batch_hosts) >= batch_size or processed == len(to_probe):
                _cache_update_from_batch(
                    batch_hosts,
                    batch_records,
                    batch_live,
                    ttl_seconds=ttl_seconds,
                    target_name=target_name,
                )
                current_batch += 1
                percent = min(47, 36 + int((current_batch / total_batches) * 11))
                emit_collection_progress(
                    progress_callback,
                    f"live-host batch {current_batch}/{total_batches}: total {len(live_hosts)} "
                    f"live hosts after {processed + skipped_count}/{len(hosts)} candidates",
                    percent,
                    processed=processed + skipped_count,
                    total=len(hosts),
                    stage_percent=int(((processed + skipped_count) / max(1, len(hosts))) * 100),
                )
                batch_hosts = []
                batch_records = []
                batch_live = set()
    return records, live_hosts


def probe_host_without_httpx(host: str, timeout_seconds: int) -> dict[str, Any] | None:
    """Fallback prober using urllib3 and explicit IPv6 connectivity checks."""
    import logging
    logger = logging.getLogger(__name__)

    candidates = [host] if "://" in host else [f"https://{host}", f"http://{host}"]

    if "://" not in host:
        try:
            last_label = host.split(".")[-1] if "." in host else host
            if not any(c.isdigit() for c in last_label):
                addr_info = socket.getaddrinfo(host, None, socket.AF_INET6)
                for info in addr_info:
                    ip6 = info[4][0]
                    candidates.append(f"https://[{ip6}]")
                    candidates.append(f"http://[{ip6}]")
        except (socket.gaierror, socket.herror, OSError) as exc:
            logger.warning("Operation failed in health.py: %s", exc, exc_info=True)  # noqa: BLE001

    pool = get_pooled_connection()
    seen = set()
    unique_candidates = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique_candidates.append(c)

    safe_candidates: list[tuple[str, str]] = []
    for candidate in unique_candidates:
        if not is_safe_url(candidate):
            logger.debug("Skipping unsafe probe candidate (SSRF guard): %s", candidate)
            continue
        safe_candidates.append((candidate, host))

    for candidate, header_host in safe_candidates:
        try:
            resp = pool.request(
                "GET",
                candidate,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                timeout=urllib3.util.Timeout(connect=timeout_seconds, read=timeout_seconds),
                retries=False,
            )
            return {
                "url": normalize_url(resp.geturl() or candidate),
                "status_code": resp.status,
                "source": "python-probe-ipv6" if "[" in candidate else "python-probe",
                "resolved_host": host,
            }
        except (
            OSError,
            urllib3.exceptions.HTTPError,
            urllib3.exceptions.MaxRetryError,
            urllib3.exceptions.NewConnectionError,
            urllib3.exceptions.ProtocolError,
            urllib3.exceptions.TimeoutError,
            TimeoutError,
        ):
            continue
    return None
