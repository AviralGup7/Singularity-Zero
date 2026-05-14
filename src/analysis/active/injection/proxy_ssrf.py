"""Proxy/relay SSRF detection.

Detects applications that act as HTTP proxies or URL fetchers and tests
them for server-side request forgery by providing attacker-controlled
URLs and checking if the application fetches them.

Vectors covered:
- URL preview endpoints (/api/preview?url=, /proxy?url=, /fetch?url=)
- Webhook testing endpoints
- RSS/Atom feed fetchers
- Image proxy endpoints
- PDF generation endpoints
- Screenshot API endpoints
"""

import logging
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.passive.runtime import ResponseCache

logger = logging.getLogger(__name__)

PROXY_PATH_PATTERNS = [
    "/proxy",
    "/fetch",
    "/preview",
    "/url-preview",
    "/read-url",
    "/embed",
    "/oembed",
    "/thumbnail",
    "/screenshot",
    "/capture",
    "/render",
    "/html-to-pdf",
    "/pdf",
    "/download",
    "/image-proxy",
    "/img-proxy",
    "/image-resize",
    "/webhook",
    "/callback",
    "/ping",
    "/health-check",
    "/url-check",
    "/link-checker",
    "/feed",
    "/rss",
    "/atom",
    "/import",
    "/import-url",
    "/webpage",
]

PROXY_QUERY_PARAMS = {
    "url",
    "uri",
    "target",
    "src",
    "source",
    "link",
    "href",
    "endpoint",
    "endpoint_url",
    "callback_url",
    "webhook_url",
    "ping_url",
    "fetch_url",
    "feed_url",
    "image_url",
    "page_url",
    "destination",
    "remote",
    "addr",
    "redirect_to",
}

INTERNAL_URLS = [
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
]


def _is_proxy_endpoint(url: str) -> bool:
    """Heuristic: does a URL look like a proxy/relay endpoint?"""
    parsed = urlparse(url)
    path_lower = parsed.path.lower()

    for pattern in PROXY_PATH_PATTERNS:
        if pattern in path_lower:
            return True

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for key, value in query_pairs:
        if key.lower() in PROXY_QUERY_PARAMS:
            lower_val = value.lower()
            if lower_val.startswith(("http://", "https://", "//")):
                return True

    return False


def _build_proxy_payloads(
    url: str,
    test_urls: list[str] | None = None,
) -> list[tuple[str, str, str]]:
    """Generate SSRF payloads for a proxy-like endpoint.

    Returns list of (param_name, original_value, test_url) triples.
    """
    test_urls = test_urls or INTERNAL_URLS
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    payloads: list[tuple[str, str, str]] = []

    for idx, (key, value) in enumerate(query_pairs):
        if key.lower() not in PROXY_QUERY_PARAMS:
            continue
        lower_val = value.lower()
        if not lower_val.startswith(("http://", "https://", "//")):
            continue

        for test_url in test_urls:
            updated = list(query_pairs)
            updated[idx] = (key, test_url)
            test_full = urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
            payloads.append((key, value, test_full))

    return payloads


def _analyze_proxy_response(
    response: dict[str, Any] | None,
    test_url: str,
    param_name: str,
    original_value: str,
) -> dict[str, Any] | None:
    if response is None:
        return None

    body = str(response.get("body_text", "") or "")
    status = int(response.get("status_code") or 0)

    indicators: list[str] = []

    if "instance-id" in body.lower() or "ami-id" in body.lower():
        indicators.append("cloud_metadata_response")
    elif "127.0.0.1" in body or "localhost" in body.lower():
        indicators.append("localhost_response")
    elif any(ip in body for ip in ("10.0.", "10.", "172.16.", "192.168.")):
        indicators.append("internal_ip_response")
    elif status != 404 and status != 400 and status != 403 and len(body) > 50:
        indicators.append("non_error_response")

    if not indicators:
        return None

    severity = "critical"
    if "cloud_metadata_response" in indicators:
        severity = "critical"
    elif "localhost_response" in indicators:
        severity = "high"
    elif "internal_ip_response" in indicators:
        severity = "high"
    else:
        severity = "medium"

    return {
        "type": "proxy_ssrf",
        "severity": severity,
        "parameter": param_name,
        "original_value": original_value,
        "payload_url": test_url,
        "response_status": status,
        "response_size": len(body),
        "indicators": indicators,
        "details": f"Proxy relay fetched {test_url} and returned status {status}",
    }


def proxy_ssrf_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    test_urls: list[str] | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test proxy/relay endpoints for SSRF.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        test_urls: Custom URLs to test (default: internal/metadata URLs).
        limit: Maximum number of findings to return.

    Returns:
        List of proxy SSRF findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    test_urls = test_urls or INTERNAL_URLS

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_entry.get("url", "")).strip()
        if not url:
            continue

        if not _is_proxy_endpoint(url):
            continue

        endpoint_sig = url.split("?")[0]
        if endpoint_sig in seen:
            continue
        seen.add(endpoint_sig)

        payloads = _build_proxy_payloads(url, test_urls)
        if not payloads:
            continue

        for param_name, original_value, test_full in payloads:
            response = response_cache.request(
                test_full,
                headers={
                    "Cache-Control": "no-cache",
                    "X-Proxy-SSRF-Probe": "1",
                },
            )

            result = _analyze_proxy_response(response, test_full, param_name, original_value)
            if result:
                result["url"] = url
                findings.append(result)
                break

    findings.sort(
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2}.get(f["severity"], 3),
            f["url"],
        )
    )
    return findings[:limit]
