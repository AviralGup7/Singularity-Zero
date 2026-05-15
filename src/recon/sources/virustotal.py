"""VirusTotal Passive DNS subdomain enumeration.

Queries the VirusTotal Intelligence API for passive DNS subdomain data.
Gracefully degrades if no API key is provided.
"""

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


async def query_virustotal_passive(
    domain: str,
    api_key: str | None = None,
    timeout: int = 30,
) -> set[str]:
    """Query VirusTotal Intelligence for passive DNS subdomains.

    Args:
        domain: Root domain to enumerate subdomains for.
        api_key: VirusTotal API key. Falls back to VT_API_KEY env var.
        timeout: HTTP request timeout in seconds.

    Returns:
        Set of discovered subdomain FQDNs.
    """
    api_key = api_key or os.environ.get("VT_API_KEY")
    if not api_key:
        logger.debug("VT_API_KEY not set, skipping VirusTotal passive DNS")
        return set()

    subdomains: set[str] = set()
    cursor: str | None = None

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": "cyber-pipeline/1.0"},
            follow_redirects=True,
        ) as client:
            for _page in range(10):  # Safety limit: max 10 pages
                params: dict[str, Any] = {"limit": 40}
                if cursor:
                    params["cursor"] = cursor

                url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
                resp = await client.get(url, headers={"x-apikey": api_key}, params=params)

                if resp.status_code == 404:
                    break
                if resp.status_code == 429:
                    logger.warning("VirusTotal rate limit hit, stopping passive DNS")
                    break
                if resp.status_code == 403:
                    logger.warning("VirusTotal API key rejected")
                    break
                if resp.status_code != 200:
                    logger.warning("VirusTotal returned HTTP %d", resp.status_code)
                    break

                data = resp.json()
                for item in data.get("data", []):
                    subdomain = item.get("id", "")
                    if subdomain:
                        subdomains.add(subdomain.lower())

                cursor = data.get("meta", {}).get("cursor")
                if not cursor:
                    break

    except httpx.RequestError as exc:
        logger.debug("VirusTotal request failed: %s", exc)

    logger.info(
        "VirusTotal passive DNS: found %d subdomains for %s",
        len(subdomains),
        domain,
    )
    return subdomains
