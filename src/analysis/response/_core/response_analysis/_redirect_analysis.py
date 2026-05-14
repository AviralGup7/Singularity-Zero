"""Redirect chain analysis and auth boundary detection."""

from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    endpoint_base_key,
    endpoint_signature,
    is_auth_flow_endpoint,
    is_noise_url,
)
from src.analysis.passive.runtime import ResponseCache


def redirect_chain_analyzer(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 24
) -> list[dict[str, Any]]:
    """Analyze redirect chains for cross-host and auth-related redirects."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url in priority_urls:
        if len(findings) >= limit:
            break
        if not url or is_noise_url(url):
            continue
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)
        response = response_cache.get(url)
        if not response:
            continue
        redirect_chain = list(response.get("redirect_chain") or [])
        final_url = str(response.get("final_url") or response.get("url") or "")
        redirect_count = int(response.get("redirect_count") or max(len(redirect_chain) - 1, 0))
        headers = {
            str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()
        }
        location = headers.get("location", "")
        if redirect_count <= 0 and not location:
            continue
        url_netloc = urlparse(url).netloc.lower()
        final_netloc = urlparse(final_url).netloc.lower() if final_url else ""
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": endpoint_base_key(url),
                "redirect_chain": redirect_chain[:6] if redirect_chain else [url, final_url],
                "redirect_count": redirect_count,
                "final_url": final_url,
                "cross_host": bool(final_url and final_netloc != url_netloc),
                "auth_related": is_auth_flow_endpoint(url) or is_auth_flow_endpoint(final_url),
            }
        )
    findings.sort(key=lambda item: (-item["redirect_count"], not item["cross_host"], item["url"]))
    return findings[:limit]


def auth_boundary_redirect_detection(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 24
) -> list[dict[str, Any]]:
    """Detect redirects that cross authentication boundaries."""
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        if len(findings) >= limit:
            break
        if not url or is_noise_url(url):
            continue
        response = response_cache.get(url)
        if not response:
            continue
        final_url = str(response.get("final_url") or response.get("url") or "")
        requested_auth = is_auth_flow_endpoint(url)
        final_auth = is_auth_flow_endpoint(final_url)
        redirect_count = int(response.get("redirect_count") or 0)
        if redirect_count <= 0 and requested_auth == final_auth:
            continue
        url_netloc = urlparse(url).netloc.lower()
        final_netloc = urlparse(final_url).netloc.lower() if final_url else ""
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "final_url": final_url,
                "redirect_count": redirect_count,
                "pre_auth_boundary": requested_auth,
                "post_auth_boundary": final_auth,
                "boundary_changed": requested_auth != final_auth,
                "signals": sorted(
                    {
                        "auth_boundary_redirect",
                        "pre_login" if requested_auth else "",
                        "post_login" if final_auth else "",
                        "cross_host" if final_netloc and url_netloc != final_netloc else "",
                    }
                    - {""}
                ),
            }
        )
    findings.sort(
        key=lambda item: (not item["boundary_changed"], -item["redirect_count"], item["url"])
    )
    return findings[:limit]
