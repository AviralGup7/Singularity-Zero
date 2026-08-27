"""RapidDNS subdomain enumeration.

Scrapes RapidDNS.io for publicly available passive DNS subdomain data.
No API key required — uses simple HTTP scraping.
"""

import logging
import re

import httpx
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None  # type: ignore[assignment]

from src.recon.domain_validation import normalize_domain as _normalize_domain

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
    domain = _normalize_domain(domain)
    if not domain:
        logger.debug("RapidDNS: invalid domain input")
        return set()
    pattern = re.compile(r"^([a-z0-9*.\-]+\." + re.escape(domain) + r")$", re.IGNORECASE)

    try:
        url = f"https://rapiddns.io/subdomain/{domain}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                logger.debug("RapidDNS returned HTTP %d", resp.status_code)
                return set()

            if BeautifulSoup is None:
                for cell in re.findall(r'<td[^>]*class=["\']hostname["\'][^>]*>(.*?)</td>', resp.text, re.DOTALL | re.IGNORECASE):
                    text = re.sub(r'<[^>]+>', ' ', cell).strip().lower()
                    if text and pattern.match(text):
                        subdomains.add(text)
                return subdomains

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
