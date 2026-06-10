"""CertSpotter (SSLMate) certificate transparency subdomain enumeration.

CertSpotter exposes a free, key-less certificate transparency search at
``https://certspotter.com/api/v0/certs?domain={domain}``.  The response
is a JSON array of certificate objects; each ``dns_names`` entry is a
candidate subdomain.  An optional API key raises rate limits and is
honored when ``CERTSPOTTER_API_KEY`` is present.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import httpx

from src.recon.domain_validation import normalize_domain as _normalize_domain

logger = logging.getLogger(__name__)

_API_URL = "https://certspotter.com/api/v0/certs"


async def query_certspotter(
    domain: str,
    api_key: str | None = None,
    timeout: int = 30,
) -> set[str]:
    """Query CertSpotter for CT-log subdomain candidates.

    Args:
        domain: Root domain to enumerate subdomains for.
        api_key: Optional CertSpotter API key.  Falls back to the
            ``CERTSPOTTER_API_KEY`` environment variable.  A key is not
            required, but increases rate limits.
        timeout: HTTP request timeout in seconds.

    Returns:
        Set of discovered subdomain FQDNs.  Empty set on any failure
        (invalid input, network error, non-200, JSON parse error).
    """
    domain = _normalize_domain(domain)
    if not domain:
        logger.debug("CertSpotter: invalid domain input")
        return set()

    api_key = api_key or os.environ.get("CERTSPOTTER_API_KEY")
    headers: dict[str, str] = {"User-Agent": "cyber-pipeline/1.0"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    subdomains: set[str] = set()
    pattern = re.compile(r"^([a-z0-9*.\-]+\." + re.escape(domain) + r")$", re.IGNORECASE)

    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, headers=headers
        ) as client:
            resp = await client.get(
                _API_URL, params={"domain": domain, "include_subdomains": "true"}
            )
            if resp.status_code == 429:
                logger.warning("CertSpotter rate limit hit, stopping")
                return set()
            if resp.status_code != 200:
                logger.debug("CertSpotter returned HTTP %d", resp.status_code)
                return set()

            try:
                payload: Any = resp.json()
            except ValueError as exc:
                logger.debug("CertSpotter JSON parse failed: %s", exc)
                return set()

            if not isinstance(payload, list):
                logger.debug("CertSpotter: unexpected payload shape")
                return set()

            for cert in payload:
                if not isinstance(cert, dict):
                    continue
                for name in cert.get("dns_names", []) or []:
                    if not isinstance(name, str):
                        continue
                    candidate = name.strip().lower().lstrip("*.")
                    if candidate and pattern.match(candidate):
                        subdomains.add(candidate)

    except httpx.RequestError as exc:
        logger.debug("CertSpotter request failed: %s", exc)

    logger.info("CertSpotter: found %d subdomains for %s", len(subdomains), domain)
    return subdomains
