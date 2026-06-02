"""URLScan provider for in-house collectors.

This provider queries urlscan.io's search API for captured pages related
to the provided host. The implementation is tolerant for testing: it
parses common JSON shapes and falls back to line-oriented heuristics.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlparse

import requests

from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.observability import emit_collection_progress
from src.recon.collectors.rate_limiter import acquire as _acquire_token
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)

URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"

_URL_RE = re.compile(r"https?://[^\s\"\'<>\\)]+", re.IGNORECASE)

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


def _parse_urlscan_json(text: str) -> list[str]:
    urls: list[str] = []
    try:
        data = json.loads(text)
    except Exception:
        # fallback: extract http(s) URLs from text/HTML
        return _URL_RE.findall(text or "")

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
            _is_safe_url(URLSCAN_SEARCH)
            resp = requests.get(URLSCAN_SEARCH, params=params, timeout=max(2, timeout_seconds))  # nosec B113
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
            if hosts_list:
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
