"""ProjectDiscovery Chaos passive DNS subdomain enumeration.

Chaos (https://cloud.projectdiscovery.io) is ProjectDiscovery's curated
dataset of forward DNS records.  The public endpoint is::

    GET https://dns.projectdiscovery.io/dns/{domain}

and returns a JSON array of subdomain FQDNs, e.g.::

    ["www.example.com", "api.example.com", ...]

An API key is required and is read from ``CHAOS_API_KEY`` (the official
ProjectDiscovery Cloud variable name).  ``PDCP_API_KEY`` is honoured as
a fallback for users exporting the key under the newer
``projectdiscovery`` tooling.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from src.recon.domain_validation import normalize_domain as _normalize_domain

logger = logging.getLogger(__name__)

_API_URL = "https://dns.projectdiscovery.io/dns/{domain}"


async def query_chaos(
    domain: str,
    api_key: str | None = None,
    timeout: int = 30,
) -> set[str]:
    """Query ProjectDiscovery Chaos for passive DNS subdomains.

    Args:
        domain: Root domain to enumerate subdomains for.
        api_key: Chaos / ProjectDiscovery Cloud API key.  Falls back
            to ``CHAOS_API_KEY`` or ``PDCP_API_KEY`` environment
            variables (in that order).
        timeout: HTTP request timeout in seconds.

    Returns:
        Set of discovered subdomain FQDNs.  Empty set when the key is
        missing, the request fails, or the response shape is unexpected.
    """
    domain = _normalize_domain(domain)
    if not domain:
        logger.debug("Chaos: invalid domain input")
        return set()

    api_key = api_key or os.environ.get("CHAOS_API_KEY") or os.environ.get("PDCP_API_KEY")
    if not api_key:
        logger.debug("CHAOS_API_KEY / PDCP_API_KEY not set, skipping ProjectDiscovery Chaos")
        return set()

    subdomains: set[str] = set()

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={
                "User-Agent": "cyber-pipeline/1.0",
                "Accept": "application/json",
                "Authorization": api_key,
            },
        ) as client:
            resp = await client.get(_API_URL.format(domain=domain))

            if resp.status_code == 401:
                logger.warning("Chaos API key rejected (HTTP 401)")
                return set()
            if resp.status_code == 403:
                logger.warning("Chaos API key lacks permission (HTTP 403)")
                return set()
            if resp.status_code == 429:
                logger.warning("Chaos rate limit hit")
                return set()
            if resp.status_code == 404:
                logger.debug("Chaos: no data for %s", domain)
                return set()
            if resp.status_code != 200:
                logger.debug("Chaos returned HTTP %d", resp.status_code)
                return set()

            try:
                payload: Any = resp.json()
            except ValueError as exc:
                logger.debug("Chaos JSON parse failed: %s", exc)
                return set()

            # Chaos returns a flat list of FQDNs.
            items: list[Any] = payload if isinstance(payload, list) else []
            if not items and isinstance(payload, dict):
                # Some proxy/wrapper deployments nest under ``domains``.
                items = payload.get("domains", []) or []

            for entry in items:
                if not isinstance(entry, str):
                    continue
                candidate = entry.strip().lower().lstrip("*.").rstrip(".")
                if not candidate:
                    continue
                # Accept only FQDNs under the apex domain (Chaos has
                # been observed to return unrelated wildcards in error
                # responses).
                if candidate == domain or candidate.endswith(f".{domain}"):
                    subdomains.add(candidate)

    except httpx.RequestError as exc:
        logger.debug("Chaos request failed: %s", exc)

    logger.info("Chaos: found %d subdomains for %s", len(subdomains), domain)
    return subdomains
