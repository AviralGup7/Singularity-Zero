"""Spyse (formerly recon-ng compatible) passive DNS subdomain enumeration.

Spyse was acquired by SecurityTrails in 2022 and the public API at
``https://api.spyse.com/v4/data/domain/{domain}/subdomains`` was retired
along with the consumer dashboard.  However, many bug-bounty
``subfinder`` and ``assetfinder`` configurations still list ``spyse``
as a source, so we keep the plugin registered for parity.

Behaviour:
    * If ``SPYSE_API_KEY`` is set we issue a single best-effort request
      to the legacy endpoint.  Most keys will be rejected (401/403) at
      this point; we log a single warning and return an empty set.
    * Without a key we short-circuit silently.

The module never raises - it always returns ``set()`` so the dynamic
registrar in ``subdomains.py`` does not error out.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

import httpx

from src.recon.domain_validation import normalize_domain as _normalize_domain

logger = logging.getLogger(__name__)

_LEGACY_URL = "https://api.spyse.com/v4/data/domain/{domain}/subdomains"


async def query_spyse(
    domain: str,
    api_key: str | None = None,
    timeout: int = 30,
) -> set[str]:
    """Query Spyse for passive DNS subdomains.

    Note:
        The public Spyse API has been sunset; this module is kept for
        pipeline parity and will only return data when an active
        ``SPYSE_API_KEY`` is supplied and the legacy endpoint still
        responds successfully.

    Args:
        domain: Root domain to enumerate subdomains for.
        api_key: Optional Spyse API key.  Falls back to the
            ``SPYSE_API_KEY`` environment variable.
        timeout: HTTP request timeout in seconds.

    Returns:
        Set of discovered subdomain FQDNs, or empty set on any failure
        or when no API key is configured.
    """
    domain = _normalize_domain(domain)
    if not domain:
        logger.debug("Spyse: invalid domain input")
        return set()

    api_key = api_key or os.environ.get("SPYSE_API_KEY")
    if not api_key:
        logger.debug("SPYSE_API_KEY not set, skipping Spyse passive DNS")
        return set()

    subdomains: set[str] = set()
    pattern = re.compile(r"^([a-z0-9*.\-]+\." + re.escape(domain) + r")$", re.IGNORECASE)

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers={
                "User-Agent": "cyber-pipeline/1.0",
                "Authorization": f"Bearer {api_key}",
            },
        ) as client:
            resp = await client.get(_LEGACY_URL.format(domain=domain))

            if resp.status_code in (401, 403):
                logger.warning(
                    "Spyse API key rejected (HTTP %d); the public Spyse API "
                    "has been sunset, returning empty set",
                    resp.status_code,
                )
                return set()
            if resp.status_code == 404:
                logger.debug("Spyse: no data for %s", domain)
                return set()
            if resp.status_code != 200:
                logger.debug("Spyse returned HTTP %d", resp.status_code)
                return set()

            try:
                payload: Any = resp.json()
            except ValueError as exc:
                logger.debug("Spyse JSON parse failed: %s", exc)
                return set()

            items = payload.get("data", {}).get("items", []) if isinstance(payload, dict) else []
            for item in items:
                if not isinstance(item, dict):
                    continue
                name = item.get("domain") or item.get("name")
                if not isinstance(name, str):
                    continue
                candidate = name.strip().lower().lstrip("*.")
                if candidate and pattern.match(candidate):
                    subdomains.add(candidate)

    except httpx.RequestError as exc:
        logger.debug("Spyse request failed: %s", exc)

    logger.info("Spyse: found %d subdomains for %s", len(subdomains), domain)
    return subdomains
