"""DNSDumpster passive DNS subdomain enumeration.

DNSDumpster (https://dnsdumpster.com) is HackerTarget's free passive DNS
recon tool.  The public web UI requires a CSRF token issued by the
landing page, so this module performs the standard two-step workflow:

    1. GET ``/``  -> extract ``csrfmiddlewaretoken`` from the form.
    2. POST ``/`` with the token + ``targetip`` field -> parse the
       returned HTML for subdomain entries in the result table.

The site is unauthenticated, but aggressively rate-limits anonymous
traffic; we keep request volume low and degrade gracefully on any
non-200 response or HTML parse failure.
"""

from __future__ import annotations

import logging
import re

import httpx
from bs4 import BeautifulSoup

from src.recon.domain_validation import normalize_domain as _normalize_domain

logger = logging.getLogger(__name__)

_CSRF_RE = re.compile(
    r'name=["\']csrfmiddlewaretoken["\'][^>]*?value=["\']([a-zA-Z0-9]+)["\']',
    re.IGNORECASE | re.DOTALL,
)


async def query_dnsdumpster(
    domain: str,
    timeout: int = 30,
) -> set[str]:
    """Query DNSDumpster for passive DNS subdomains.

    Args:
        domain: Root domain to enumerate subdomains for.
        timeout: HTTP request timeout in seconds (used for both the CSRF
            fetch and the search submission).

    Returns:
        Set of discovered subdomain FQDNs.  Empty set on any failure
        (invalid input, network error, CSRF/parse error, non-200).
    """
    domain = _normalize_domain(domain)
    if not domain:
        logger.debug("DNSDumpster: invalid domain input")
        return set()

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; cyber-pipeline/1.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": "https://dnsdumpster.com/",
    }
    subdomains: set[str] = set()
    pattern = re.compile(
        r"^([a-z0-9*.\-]+\." + re.escape(domain) + r")$", re.IGNORECASE
    )

    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, headers=headers
        ) as client:
            landing = await client.get("https://dnsdumpster.com/")
            if landing.status_code != 200:
                logger.debug("DNSDumpster landing returned HTTP %d", landing.status_code)
                return set()

            match = _CSRF_RE.search(landing.text)
            if not match:
                logger.debug("DNSDumpster: could not extract CSRF token")
                return set()
            csrf_token: str = match.group(1)

            resp = await client.post(
                "https://dnsdumpster.com/",
                data={
                    "csrfmiddlewaretoken": csrf_token,
                    "targetip": domain,
                    "user": "free",
                },
                headers={**headers, "Cookie": f"csrftoken={csrf_token}"},
            )
            if resp.status_code != 200:
                logger.debug("DNSDumpster search returned HTTP %d", resp.status_code)
                return set()

            subdomains = _parse_subdomains(resp.text, domain, pattern)

    except httpx.RequestError as exc:
        logger.debug("DNSDumpster request failed: %s", exc)
    except Exception as exc:  # parsing or unexpected layout
        logger.debug("DNSDumpster parsing error: %s", exc)

    logger.info("DNSDumpster: found %d subdomains for %s", len(subdomains), domain)
    return subdomains


def _parse_subdomains(
    html: str, domain: str, pattern: re.Pattern[str]
) -> set[str]:
    """Pull subdomain FQDNs out of the DNSDumpster result page.

    DNSDumpster renders a ``<table class="table">`` containing rows with
    a ``<td class="col-md-4">`` cell that holds an ``<a>`` or text node
    for the host.  We accept any candidate that matches ``<sub>.<domain>``
    after lowercasing; wildcard entries are stripped.
    """
    found: set[str] = set()
    soup = BeautifulSoup(html, "html.parser")
    for table in soup.find_all("table"):
        for td in table.find_all("td"):
            text = td.get_text(" ", strip=True).lower()
            if not text or "." not in text:
                continue
            for line in text.split():
                candidate = line.lstrip("*.").strip()
                if candidate and pattern.match(candidate):
                    found.add(candidate)
    return found
