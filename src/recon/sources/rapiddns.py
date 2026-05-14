"""RapidDNS subdomain enumeration.

Scrapes RapidDNS.io for publicly available passive DNS subdomain data.
No API key required — uses simple HTTP scraping.
"""

import logging
import re

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


async def query_rapiddns(
    domain: str,
    timeout: int = 30,
) -> set[str]:
    """Query RapidDNS for passive DNS subdomains.

    Args:
        domain: Root domain to enumerate subdomains for.
        timeout: HTTP request timeout in seconds.

    Returns:
        Set of discovered subdomain FQDNs.
    """
    subdomains: set[str] = set()
    pattern = re.compile(r"^([a-z0-9*.\-]+\." + re.escape(domain) + r")$", re.IGNORECASE)

    try:
        url = f"https://rapiddns.io/subdomain/{domain}"
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; cyber-pipeline/1.0)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers=headers,
        ) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                logger.debug("RapidDNS returned HTTP %d", resp.status_code)
                return set()

            soup = BeautifulSoup(resp.text, "html.parser")
            table = soup.find("table", id="table")
            if table:
                for row in table.find_all("tr"):
                    td = row.find("td", class_="hostname")
                    if td:
                        a = td.find("a", href=True)
                        hostname = a.text.strip() if a else td.text.strip()
                        if hostname and pattern.match(hostname):
                            subdomains.add(hostname.lower())

    except httpx.RequestError as exc:
        logger.debug("RapidDNS request failed: %s", exc)
    except Exception as exc:
        logger.debug("RapidDNS parsing error: %s", exc)

    logger.info(
        "RapidDNS: found %d subdomains for %s",
        len(subdomains),
        domain,
    )
    return subdomains
