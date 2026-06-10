"""SubdomainCenter free certificate transparency log API client."""

from __future__ import annotations

import logging
import re

import httpx

from src.recon.domain_validation import normalize_domain as _normalize_domain

logger = logging.getLogger(__name__)

_API_URL = "https://api.subdomain.center/?domain={domain}"


async def query_subdomain_center(
    domain: str,
    timeout: int = 30,
) -> set[str]:
    domain = _normalize_domain(domain)
    if not domain:
        return set()
    subdomains: set[str] = set()
    pattern = re.compile(r"^([a-z0-9*.\-]+\." + re.escape(domain) + r")$", re.IGNORECASE)
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, headers={"User-Agent": "cyber-pipeline/1.0"}
        ) as client:
            resp = await client.get(_API_URL.format(domain=domain))
            if resp.status_code == 429:
                return set()
            if resp.status_code != 200:
                return set()
            try:
                payload = resp.json()
            except ValueError:
                for line in resp.text.splitlines():
                    cand = line.strip().lower().lstrip("*.").rstrip(".")
                    if cand and pattern.match(cand):
                        subdomains.add(cand)
                return subdomains
            if isinstance(payload, list):
                items = payload
            elif isinstance(payload, dict):
                items = (
                    payload.get("subdomains") or payload.get("data") or payload.get("result") or []
                )
            else:
                return set()
            for entry in items:
                if isinstance(entry, str):
                    cand = entry.strip().lower().lstrip("*.").rstrip(".")
                    if cand and pattern.match(cand):
                        subdomains.add(cand)
                elif isinstance(entry, dict):
                    name = entry.get("domain") or entry.get("subdomain") or entry.get("name") or ""
                    cand = name.strip().lower().lstrip("*.").rstrip(".")
                    if cand and pattern.match(cand):
                        subdomains.add(cand)
    except httpx.RequestError as exc:
        logger.warning("Operation failed in subdomain_center.py: %s", exc, exc_info=True)  # noqa: BLE001
    logger.info("SubdomainCenter: found %d subdomains for %s", len(subdomains), domain)
    return subdomains
