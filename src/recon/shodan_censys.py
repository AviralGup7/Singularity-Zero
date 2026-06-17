"""Shodan / Censys / LeakIX cross-reference for live asset discovery.

Bug-bounty recon benefits massively from cross-referencing what
*we* discovered with what internet-wide scanners have indexed. The
three free / freemium sources we integrate here are:

* **Shodan** — `https://api.shodan.io/`. Requires a paid API key but
  the free tier (1 query / month) is enough for occasional
  cross-references. The module reads ``SHODAN_API_KEY`` from the
  environment when the user did not pass one explicitly.
* **Censys** — `https://search.censys.io/api/v1/`. Requires an API ID
  + secret. Reads ``CENSYS_API_ID`` and ``CENSYS_API_SECRET`` from
  the environment.
* **LeakIX** — `https://leakix.net/api/`. Free, no key required for
  the public search endpoint. Returns very fresh results (often
  within hours of a service being exposed).

The module exposes a unified :func:`cross_reference_ips` function
that fans out across the three sources, deduplicates the result, and
returns a flat list of cross-reference findings.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable
from typing import Any

import requests

from src.infrastructure.execution_engine.shared_pool import get_shared_executor
from src.recon.dnsx_wildcard import is_public_ip

logger = logging.getLogger(__name__)

SHODAN_HOST_ENDPOINT = "https://api.shodan.io/shodan/host/{ip}"
SHODAN_SEARCH_ENDPOINT = "https://api.shodan.io/shodan/host/search"
CENSYS_HOST_SEARCH_ENDPOINT = "https://search.censys.io/api/v1/search/ipv4"
LEAKIX_SEARCH_ENDPOINT = "https://leakix.net/api/services"

DEFAULT_TIMEOUT = 8
DEFAULT_CONCURRENCY = 3


# ---------------------------------------------------------------------------
# Per-source clients
# ---------------------------------------------------------------------------


def _shodan_lookup(
    ip: str,
    *,
    api_key: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    if not api_key:
        api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return []
    if not is_public_ip(ip):
        return []
    try:
        resp = requests.get(  # nosec B113
            SHODAN_HOST_ENDPOINT.format(ip=ip),
            params={"key": api_key, "minify": True},
            timeout=max(2, int(timeout)),
        )
    except requests.RequestException as exc:
        logger.debug("Shodan lookup failed for %s: %s", ip, exc)
        return []
    if resp.status_code != 200:
        return []
    try:
        data = resp.json()
    except json.JSONDecodeError:
        return []
    ports = data.get("ports") or []
    hostnames = data.get("hostnames") or []
    vulns = data.get("vulns") or []
    findings: list[dict[str, Any]] = [
        {
            "source": "shodan",
            "ip": ip,
            "ports": [int(p) for p in ports if isinstance(p, (int, str))],
            "hostnames": [str(h) for h in hostnames if isinstance(h, str)],
            "vulns": [str(v) for v in vulns if isinstance(v, str)],
            "org": data.get("org", ""),
            "asn": data.get("asn", ""),
            "os": data.get("os", ""),
        }
    ]
    return findings


def _censys_lookup(
    ip: str,
    *,
    api_id: str | None = None,
    api_secret: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    api_id = api_id or os.environ.get("CENSYS_API_ID")
    api_secret = api_secret or os.environ.get("CENSYS_API_SECRET")
    if not (api_id and api_secret):
        return []
    if not is_public_ip(ip):
        return []
    try:
        resp = requests.post(  # nosec B113
            CENSYS_HOST_SEARCH_ENDPOINT,
            auth=(api_id, api_secret),
            json={"query": f"ip: {ip}"},
            timeout=max(2, int(timeout)),
        )
    except requests.RequestException as exc:
        logger.debug("Censys lookup failed for %s: %s", ip, exc)
        return []
    if resp.status_code != 200:
        return []
    try:
        data = resp.json()
    except json.JSONDecodeError:
        return []
    services = (data.get("result") or {}).get("services") or []
    findings: list[dict[str, Any]] = []
    for svc in services:
        if not isinstance(svc, dict):
            continue
        findings.append(
            {
                "source": "censys",
                "ip": ip,
                "port": svc.get("port"),
                "service_name": svc.get("service_name", ""),
                "banner": str(svc.get("banner", ""))[:300],
                "tls": bool(svc.get("tls")),
            }
        )
    return findings


def _leakix_lookup(
    query: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict[str, Any]]:
    """LeakIX search by domain or IP keyword.

    The LeakIX search API accepts a free-form ``scope`` parameter;
    we use ``domain:example.com`` or a bare IP. LeakIX is keyed on
    the X-API-Key header (optional) but works without it on a
    reduced rate limit.
    """
    headers = {
        "Accept": "application/json",
        "User-Agent": "cyber-pipeline/2.0 (leakix)",
    }
    api_key = os.environ.get("LEAKIX_API_KEY")
    if api_key:
        headers["api-key"] = api_key
    try:
        resp = requests.get(  # nosec B113
            LEAKIX_SEARCH_ENDPOINT,
            params={"scope": query, "pages": 1},
            headers=headers,
            timeout=max(2, int(timeout)),
        )
    except requests.RequestException as exc:
        logger.debug("LeakIX lookup failed for %s: %s", query, exc)
        return []
    if resp.status_code != 200:
        return []
    try:
        data = resp.json()
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    findings: list[dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        findings.append(
            {
                "source": "leakix",
                "ip": entry.get("ip", ""),
                "port": entry.get("port"),
                "protocol": entry.get("protocol", ""),
                "summary": entry.get("summary", ""),
                "host": entry.get("host") or entry.get("domain") or "",
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def cross_reference_ips(
    ips: Iterable[str],
    *,
    shodan_api_key: str | None = None,
    censys_api_id: str | None = None,
    censys_api_secret: str | None = None,
    enable_shodan: bool = True,
    enable_censys: bool = True,
    enable_leakix: bool = True,
    max_workers: int = DEFAULT_CONCURRENCY,
) -> list[dict[str, Any]]:
    """Cross-reference a list of IPs against Shodan / Censys / LeakIX.

    Args:
        ips: IPv4 / IPv6 literals to look up.
        shodan_api_key: Override the ``SHODAN_API_KEY`` env var.
        censys_api_id: Override the ``CENSYS_API_ID`` env var.
        censys_api_secret: Override the ``CENSYS_API_SECRET`` env var.
        enable_shodan: Skip Shodan entirely when False.
        enable_censys: Skip Censys entirely when False.
        enable_leakix: Skip LeakIX entirely when False.
        max_workers: Max concurrent HTTP requests.

    Returns:
        Flat list of finding dicts, one per service observed.
    """
    ip_list = [ip for ip in {ip.strip() for ip in ips} if ip and is_public_ip(ip)]
    if not ip_list:
        return []

    findings: list[dict[str, Any]] = []
    workers = max(1, min(max_workers, len(ip_list)))

    def _all_for_ip(ip: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        if enable_shodan:
            results.extend(_shodan_lookup(ip, api_key=shodan_api_key))
        if enable_censys:
            results.extend(_censys_lookup(ip, api_id=censys_api_id, api_secret=censys_api_secret))
        if enable_leakix:
            results.extend(_leakix_lookup(ip))
        return results

    ex = get_shared_executor()
    futures = [ex.submit(_all_for_ip, ip) for ip in ip_list]
    for fut in futures:
        try:
            findings.extend(fut.result())
        except Exception as exc:  # noqa: BLE001
            logger.debug("Cross-reference future failed: %s", exc)
    return findings


def cross_reference_domain(
    domain: str,
    *,
    shodan_api_key: str | None = None,
    enable_leakix: bool = True,
) -> list[dict[str, Any]]:
    """Cross-reference a domain via Shodan (by hostname) and LeakIX.

    Used when no IPs are known yet (e.g. before the live-host phase
    has run). The function pulls back hostnames the third parties
    associate with the domain so they can be folded back into the
    main subdomain set.
    """
    out: list[dict[str, Any]] = []
    if not domain:
        return out
    if enable_leakix:
        out.extend(_leakix_lookup(f"domain:{domain}"))
    if shodan_api_key or os.environ.get("SHODAN_API_KEY"):
        try:
            resp = requests.get(  # nosec B113
                SHODAN_SEARCH_ENDPOINT,
                params={
                    "key": shodan_api_key or os.environ.get("SHODAN_API_KEY"),
                    "query": f"hostname:{domain}",
                },
                timeout=DEFAULT_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                for match in data.get("matches") or []:
                    if not isinstance(match, dict):
                        continue
                    out.append(
                        {
                            "source": "shodan",
                            "ip": match.get("ip_str", ""),
                            "port": match.get("port"),
                            "hostnames": match.get("hostnames", []),
                            "org": match.get("org", ""),
                            "asn": match.get("asn", ""),
                        }
                    )
        except requests.RequestException as exc:
            logger.debug("Shodan domain lookup failed for %s: %s", domain, exc)
    return out


__all__ = [
    "cross_reference_domain",
    "cross_reference_ips",
]
