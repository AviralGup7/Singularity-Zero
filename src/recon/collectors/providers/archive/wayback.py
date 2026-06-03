"""Minimal Wayback CDX provider used by the in-house collector.

This module implements a small client that queries the Wayback CDX
endpoint for a list of captured originals for a host. The goal is to
provide a simple, testable replacement for archive-based URL collection
without copying external CLI code.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlparse

import requests

from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.observability import emit_collection_progress
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)

CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
DEFAULT_MAX_RETRIES = 2
DEFAULT_BACKOFF_SECONDS = 0.5

# SSRF-protection: schemes and private/loopback/link-local network ranges.
_ALLOWED_SCHEMES = {"http", "https"}
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_safe_url(url: str) -> None:
    """Raise ValueError if *url* resolves to a disallowed target.

    Checks scheme, then resolves DNS and verifies the returned addresses
    are not in private/loopback/link-local ranges.
    """
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"Disallowed URL scheme: {parsed.scheme!r} (only http/https allowed)")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Cannot parse hostname from URL: {url}")
    try:
        # Try IPv4/IPv6 literal first, otherwise resolve via DNS.
        try:
            addr = ipaddress.ip_address(hostname)
            hosts = [addr]
        except ValueError:
            hosts = []
            for family_info in socket.getaddrinfo(
                hostname, parsed.port or 443, proto=socket.IPPROTO_TCP
            ):
                addr_str = family_info[4][0]
                try:
                    hosts.append(ipaddress.ip_address(addr_str))
                except ValueError:
                    continue
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for {hostname}: {exc}") from exc

    for addr in hosts:
        for network in _BLOCKED_NETWORKS:
            if addr in network:
                raise ValueError(f"URL resolves to blocked address {addr} in {network}: {url}")


def _parse_cdx_json(text: str) -> list[str]:
    """Parse typical Wayback CDX JSON output into a list of original URLs.

    The CDX "output=json" format commonly returns an array of arrays; the
    first row may be field names. This parser tries to handle the common
    shapes and falls back to line-oriented heuristics.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        logger.warning(
            "wayback: JSON parse error, response text (truncated): %s", (text or "")[:500]
        )
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


_cdx_safe_checked = False


def _collect_for_host(host: str, timeout_seconds: int, per_host_limit: int) -> set[str]:
    global _cdx_safe_checked
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

    # Performance #5: Only check safety once per session to avoid thousands of redundant DNS queries
    if not _cdx_safe_checked:
        try:
            _is_safe_url(CDX_ENDPOINT)
            _cdx_safe_checked = True
        except ValueError as e:
            logger.error("Wayback: CDX endpoint safety check failed: %s", e)
            return set()

    for attempt in range(1, attempts + 1):
        collector_metrics.increment_requests("wayback")
        try:
            resp = requests.get(CDX_ENDPOINT, params=params, timeout=max(2, timeout_seconds))  # nosec B113
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

    if resp is None:
        return set()
    try:
        resp.raise_for_status()
    except requests.RequestException:
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
            delta = len(discovered) - before
            if delta > 0:
                collector_metrics.increment_urls("wayback", delta)
            if hosts_list:
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
