"""Subdomain takeover detection module.

Scans discovered subdomains for potential takeover vulnerabilities by
checking DNS CNAME records against known cloud service patterns and
making HTTP requests to detect provider-specific error messages.

Usage:
    from src.recon.takeover import detect_takeover

    findings = await detect_takeover(subdomains)
"""

import asyncio
import logging
from typing import Any

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

from src.pipeline.services.tool_execution import ToolInvocation, run_external_tool

logger = logging.getLogger(__name__)

TAKEOVER_PATTERNS: list[dict[str, Any]] = [
    {
        "service": "AWS S3",
        "cname_pattern": ".s3.amazonaws.com",
        "http_indicators": ["NoSuchBucket", "The specified bucket does not exist"],
    },
    {
        "service": "Heroku",
        "cname_pattern": ".herokudns.com",
        "http_indicators": ["herokucdn.com/error-pages/no-such-app.html"],
    },
    {
        "service": "GitHub Pages",
        "cname_pattern": ".github.io",
        "http_indicators": ["There isn't a GitHub Pages site here"],
    },
    {
        "service": "Azure",
        "cname_pattern": ".azurewebsites.net",
        "http_indicators": ["404 Web Site not found"],
    },
    {
        "service": "Bitbucket",
        "cname_pattern": ".bitbucket.io",
        "http_indicators": ["Repository not found"],
    },
    {
        "service": "Shopify",
        "cname_pattern": ".myshopify.com",
        "http_indicators": ["Sorry, this shop is closed"],
    },
    {
        "service": "Tumbler",
        "cname_pattern": ".tumblr.com",
        "http_indicators": ["There's nothing here"],
    },
    {
        "service": "AWS CloudFront",
        "cname_pattern": ".cloudfront.net",
        "http_indicators": ["ERROR: The request could not be satisfied"],
    },
    {
        "service": "Pantheon",
        "cname_pattern": ".pantheonsite.io",
        "http_indicators": ["The gods are wise"],
    },
    {
        "service": "Zendesk",
        "cname_pattern": ".zendesk.com",
        "http_indicators": ["Help Center Closed"],
    },
]


async def _resolve_cname(subdomain: str) -> str | None:
    """Resolve CNAME using nslookup via run_external_tool."""
    invocation = ToolInvocation(
        tool_name="nslookup",
        args=["-type=CNAME", subdomain],
        timeout_seconds=10,
    )
    try:
        result = await run_external_tool(invocation)
        if result.timed_out or not result.ok:
            return None
        for line in result.stdout.splitlines():
            line = line.strip()
            if "canonical name" in line.lower():
                parts = line.split("=", 1)
                if len(parts) == 2:
                    return parts[1].strip().rstrip(".")
    except Exception as e:
        logger.debug("nslookup via run_external_tool failed for %s: %s", subdomain, e)
    return None


def _match_cname_pattern(cname: str, pattern: str) -> bool:
    """Check if a CNAME matches a provider-specific pattern.

    Args:
        cname: The resolved CNAME record.
        pattern: The pattern to match (e.g., '.s3.amazonaws.com').

    Returns:
        True if the CNAME ends with the pattern.
    """
    return cname.lower().endswith(pattern.lower())


async def _check_http_indicators(
    subdomain: str, indicators: list[str], timeout: float = 10.0
) -> list[str]:
    """Make HTTP requests and check for provider-specific error messages.

    Args:
        subdomain: The subdomain to check.
        indicators: List of HTTP response indicators to look for.
        timeout: Request timeout in seconds.

    Returns:
        List of matched indicators.
    """
    if httpx is None:
        return []

    matched: list[str] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                response = await client.get(url)
                body = response.text
                for indicator in indicators:
                    if indicator.lower() in body.lower():
                        matched.append(indicator)
                if matched:
                    break
        except httpx.RequestError as e:
            logger.debug("HTTP request failed for %s: %s", url, e)
            continue
        except Exception as e:
            # Unexpected errors should be logged for debugging
            logger.debug("Unexpected error fetching %s: %s", url, e)
            continue

    return matched


async def _check_single_subdomain(
    subdomain: str, patterns: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Check a single subdomain against all takeover patterns.

    Args:
        subdomain: The subdomain to check.
        patterns: List of takeover pattern definitions.

    Returns:
        List of finding dicts for this subdomain.
    """
    findings: list[dict[str, Any]] = []

    cname = await _resolve_cname(subdomain)
    if not cname:
        return findings

    for pattern in patterns:
        if not _match_cname_pattern(cname, pattern["cname_pattern"]):
            continue

        matched_indicators = await _check_http_indicators(subdomain, pattern["http_indicators"])

        findings.append(
            {
                "subdomain": subdomain,
                "service": pattern["service"],
                "cname": cname,
                "indicators_matched": matched_indicators,
                "vulnerable": len(matched_indicators) > 0,
            }
        )

    return findings


async def detect_takeover(
    subdomains: set[str], patterns: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Detect potential subdomain takeover vulnerabilities.

    For each subdomain:
    1. Resolves DNS and checks CNAME records.
    2. Identifies CNAMEs pointing to cloud services.
    3. Makes HTTP requests and checks for provider-specific takeover error messages.

    Args:
        subdomains: Set of discovered subdomains to check.
        patterns: Optional override of takeover patterns. Uses defaults if None.

    Returns:
        List of finding dicts with keys: subdomain, service, cname,
        indicators_matched, vulnerable.
    """
    if patterns is None:
        patterns = TAKEOVER_PATTERNS

    all_findings: list[dict[str, Any]] = []

    tasks = [_check_single_subdomain(sd, patterns) for sd in sorted(subdomains)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            continue
        if isinstance(result, list):
            all_findings.extend(result)

    return all_findings
