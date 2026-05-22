"""CDN/WAF detection module for recon pipeline.

Identifies Content Delivery Networks (CDNs) and Web Application Firewalls
(WAFs) protecting target hosts. This information is critical because:
- CDN origins may be discovered and bypass the CDN entirely
- WAF presence affects exploitability scoring
- Different WAFs have different bypass techniques
- CDN edge servers vs origin servers have different security postures
"""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

from src.core.frontier.waf_patterns import CDN_WAF_PATTERNS


async def detect_waf_cdn(
    urls: list[str],
    timeout: float = 10.0,
    max_urls: int = 100,
) -> list[dict[str, Any]]:
    """Detect CDN/WAF presence for a list of URLs.

    Analyzes response headers, cookies, and body content against known
    patterns for major CDN and WAF providers.

    Args:
        urls: List of URLs to test.
        timeout: Per-request timeout in seconds.
        max_urls: Maximum number of URLs to test.

    Returns:
        List of finding dicts with keys: url, provider, detection_method,
        confidence, details.
    """
    if not urls:
        return []

    results: list[dict[str, Any]] = []

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (compatible; cyber-pipeline/1.0; +https://github.com/cyber-pipeline)"
            ),
        },
    ) as client:
        for url in urls[:max_urls]:
            try:
                resp = await client.get(url)
                findings = _analyze_response(url, resp)
                results.extend(findings)
            except httpx.RequestError:
                continue

    logger.info(
        "CDN/WAF detection: tested %d URLs, found %d providers",
        min(len(urls), max_urls),
        len(results),
    )
    return results


def _analyze_response(
    url: str,
    resp: httpx.Response,
) -> list[dict[str, Any]]:
    """Analyze a single HTTP response for WAF/CDN signatures."""
    findings: list[dict[str, Any]] = []

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    cookies_lower = {k.lower(): v for k, v in resp.cookies.items()}
    body_lower = (resp.text or "").lower()

    for provider, patterns in CDN_WAF_PATTERNS.items():
        header_score = 0
        cookie_score = 0
        body_score = 0

        # Check headers
        header_patterns = patterns.get("headers", [])
        for pattern in header_patterns:
            if any(pattern.lower() in h for h in headers_lower):
                header_score += 1

        # Check cookies
        cookie_patterns = patterns.get("cookies", [])
        for pattern in cookie_patterns:
            if pattern.lower() in cookies_lower:
                cookie_score += 1

        # Check body
        body_patterns = patterns.get("body", [])
        for pattern in body_patterns:
            if pattern.lower() in body_lower:
                body_score += 1

        total_score = header_score + cookie_score + body_score
        if total_score > 0:
            # Determine detection method and confidence
            if header_score > 0 and cookie_score > 0:
                method = "headers+cookies"
                confidence = 1.0
            elif header_score > 0:
                method = "headers"
                confidence = 0.9
            elif cookie_score > 0:
                method = "cookies"
                confidence = 0.8
            else:
                method = "body"
                confidence = 0.7

            findings.append(
                {
                    "url": url,
                    "provider": provider,
                    "detection_method": method,
                    "confidence": confidence,
                    "details": {
                        "header_matches": min(header_score, len(header_patterns)),
                        "cookie_matches": min(cookie_score, len(cookie_patterns)),
                        "body_matches": min(body_score, len(body_patterns)),
                        "server_header": headers_lower.get("server", ""),
                    },
                }
            )

    return findings


def build_waf_cdn_report(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a structured WAF/CDN report from detection results.

    Args:
        findings: Detection findings from detect_waf_cdn.

    Returns:
        Report dict with per-provider counts and URL breakdowns.
    """
    by_provider: dict[str, list[str]] = {}
    total_urls_tested = 0
    urls_with_waf: set[str] = set()

    for finding in findings:
        url = finding["url"]
        provider = finding["provider"]
        by_provider.setdefault(provider, []).append(url)
        urls_with_waf.add(url)

    total_urls_tested = len(urls_with_waf)
    unique_providers = set(by_provider.keys())

    return {
        "total_urls_tested": total_urls_tested,
        "urls_protected": len(urls_with_waf),
        "unique_providers": sorted(unique_providers),
        "by_provider": {
            provider: {"urls": urls, "count": len(urls)} for provider, urls in by_provider.items()
        },
    }
