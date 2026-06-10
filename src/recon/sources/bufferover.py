"""BufferOver (tls.bufferover.run) passive DNS subdomain enumeration.

BufferOver exposes a free, key-less RDAP + passive-DNS feed at
``https://tls.bufferover.run``.  The DNS endpoint returns a JSON object
of the form::

    {
      "Results": [
        "ip,subdomain.example.com",
        "ip,another.example.com"
      ],
      "Meta": {...}
    }

We also pull the TLS (certificate) endpoint to broaden coverage, since
BufferOver indexes both sources.  No authentication is required for the
free tier, but the service is rate-limited; we cap responses gracefully.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from src.recon.domain_validation import normalize_domain as _normalize_domain

logger = logging.getLogger(__name__)

_DNS_URL = "https://tls.bufferover.run/dns?q=/{domain}"
_TLS_URL = "https://tls.bufferover.run/tls?q={domain}"


async def query_bufferover(
    domain: str,
    timeout: int = 30,
) -> set[str]:
    """Query BufferOver for passive DNS and certificate subdomains.

    Args:
        domain: Root domain to enumerate subdomains for.
        timeout: HTTP request timeout in seconds.

    Returns:
        Set of discovered subdomain FQDNs.  Empty set on any failure
        (invalid input, network error, non-200, JSON parse error).
    """
    domain = _normalize_domain(domain)
    if not domain:
        logger.debug("BufferOver: invalid domain input")
        return set()

    headers = {"User-Agent": "cyber-pipeline/1.0"}
    subdomains: set[str] = set()
    pattern = re.compile(r"^([a-z0-9*.\-]+\." + re.escape(domain) + r")$", re.IGNORECASE)

    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, headers=headers
        ) as client:
            for url in (_DNS_URL.format(domain=domain), _TLS_URL.format(domain=domain)):
                resp = await client.get(url)
                if resp.status_code == 429:
                    logger.debug("BufferOver rate limited; stopping")
                    break
                if resp.status_code != 200:
                    logger.debug("BufferOver returned HTTP %d for %s", resp.status_code, url)
                    continue

                try:
                    data = resp.json()
                except ValueError as exc:
                    logger.debug("BufferOver JSON parse failed: %s", exc)
                    continue

                subdomains.update(_extract_subdomains(data, pattern))

    except httpx.RequestError as exc:
        logger.debug("BufferOver request failed: %s", exc)

    logger.info("BufferOver: found %d subdomains for %s", len(subdomains), domain)
    return subdomains


def _extract_subdomains(data: Any, pattern: re.Pattern[str]) -> set[str]:
    """Parse BufferOver's ``Results`` array of comma-joined strings."""
    found: set[str] = set()
    results = data.get("Results", []) if isinstance(data, dict) else []
    if not isinstance(results, list):
        return found
    for entry in results:
        if not isinstance(entry, str):
            continue
        # BufferOver emits ``"<ip>,<fqdn>"`` rows.  Some entries contain
        # multiple commas (e.g. CNAME chains) so we take the last token
        # as the candidate FQDN.
        parts = entry.split(",")
        for part in parts:
            candidate = part.strip().lower().lstrip("*.")
            if candidate and pattern.match(candidate):
                found.add(candidate)
    return found
