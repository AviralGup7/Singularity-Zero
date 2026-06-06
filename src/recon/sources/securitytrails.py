"""SecurityTrails passive DNS subdomain enumeration.

SecurityTrails (https://securitytrails.com) maintains one of the most
comprehensive passive DNS, historical WHOIS, and ASN datasets.  The
subdomain endpoint is::

    GET https://api.securitytrails.com/v1/domain/{domain}/subdomains

and returns a JSON document shaped like::

    {
      "subdomains": ["www", "api", "mail"],
      "meta": {...}
    }

Each entry is a left-most label that must be joined with the apex
domain.  An API key is **required** - subscribers get a key from the
SecurityTrails dashboard.  We honour ``SECURITYTRAILS_API_KEY`` from the
environment when no explicit key is passed.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from src.recon.domain_validation import normalize_domain as _normalize_domain

logger = logging.getLogger(__name__)

_API_URL = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"


async def query_securitytrails(
    domain: str,
    api_key: str | None = None,
    timeout: int = 30,
) -> set[str]:
    """Query SecurityTrails for passive DNS subdomains.

    Args:
        domain: Root domain to enumerate subdomains for.
        api_key: SecurityTrails API key.  Falls back to the
            ``SECURITYTRAILS_API_KEY`` environment variable.
        timeout: HTTP request timeout in seconds.

    Returns:
        Set of discovered subdomain FQDNs.  Empty set when the key is
        missing, the request fails, or the response shape is unexpected.
    """
    domain = _normalize_domain(domain)
    if not domain:
        logger.debug("SecurityTrails: invalid domain input")
        return set()

    api_key = api_key or os.environ.get("SECURITYTRAILS_API_KEY")
    if not api_key:
        logger.debug("SECURITYTRAILS_API_KEY not set, skipping SecurityTrails")
        return set()

    subdomains: set[str] = set()

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={
                "User-Agent": "cyber-pipeline/1.0",
                "Accept": "application/json",
                "APIKEY": api_key,
            },
        ) as client:
            resp = await client.get(_API_URL.format(domain=domain))

            if resp.status_code == 401:
                logger.warning("SecurityTrails API key rejected (HTTP 401)")
                return set()
            if resp.status_code == 403:
                logger.warning("SecurityTrails API key lacks permission (HTTP 403)")
                return set()
            if resp.status_code == 429:
                logger.warning("SecurityTrails rate limit hit")
                return set()
            if resp.status_code == 404:
                logger.debug("SecurityTrails: no data for %s", domain)
                return set()
            if resp.status_code != 200:
                logger.debug("SecurityTrails returned HTTP %d", resp.status_code)
                return set()

            try:
                data: Any = resp.json()
            except ValueError as exc:
                logger.debug("SecurityTrails JSON parse failed: %s", exc)
                return set()

            if not isinstance(data, dict):
                logger.debug("SecurityTrails: unexpected payload shape")
                return set()

            for label in data.get("subdomains", []) or []:
                if not isinstance(label, str) or not label:
                    continue
                # SecurityTrails returns left-most labels, e.g. "www"
                # for "www.example.com".  Filter obvious garbage, then
                # join with the apex domain.
                clean_label = label.strip().lower().lstrip("*.").rstrip(".")
                if not clean_label or "." in clean_label:
                    # Already an FQDN or path-like: accept only the
                    # bare-FQDN variant.
                    if clean_label.endswith(f".{domain}") or clean_label == domain:
                        subdomains.add(clean_label)
                    continue
                subdomains.add(f"{clean_label}.{domain}")

    except httpx.RequestError as exc:
        logger.debug("SecurityTrails request failed: %s", exc)

    logger.info(
        "SecurityTrails: found %d subdomains for %s", len(subdomains), domain
    )
    return subdomains
