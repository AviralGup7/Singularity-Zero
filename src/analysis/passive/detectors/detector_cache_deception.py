"""Web cache deception detector for OWASP A05: Security Misconfiguration.

Passively analyzes URLs and HTTP responses for web cache deception vulnerabilities,
including endpoints with static file extensions returning dynamic content,
missing Vary headers on mixed content, and public cache headers on authenticated endpoints.
"""

import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_signature,
    is_auth_flow_endpoint,
    is_noise_url,
    normalized_confidence,
)

_STATIC_EXTENSIONS = (
    ".css",
    ".js",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".webm",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".map",
)

_DYNAMIC_PATH_KEYWORDS = (
    "/account",
    "/profile",
    "/user",
    "/dashboard",
    "/settings",
    "/api/",
    "/graphql",
    "/admin",
    "/order",
    "/payment",
    "/checkout",
    "/cart",
    "/billing",
    "/subscription",
    "/membership",
    "/wallet",
    "/message",
    "/inbox",
    "/notification",
    "/activity",
    "/history",
    "/transaction",
    "/statement",
    "/report",
    "/analytics",
)

_CACHE_DECEPTION_PATTERN_RE = re.compile(
    r"(?:(?:/account|/profile|/user|/dashboard|/settings|/api/|/graphql|/admin|/order|/payment|/checkout|/cart|/billing|/subscription|/membership|/wallet|/message|/inbox|/notification|/activity|/history|/transaction|/statement|/report|/analytics)[^?]*\.(?:css|js|jpg|jpeg|png|gif|svg|ico|woff|woff2|pdf|map))",
    re.IGNORECASE,
)

_PUBLIC_CACHE_RE = re.compile(r"(?:public|s-maxage|must-revalidate)", re.IGNORECASE)
_NO_CACHE_RE = re.compile(r"(?:no-store|no-cache|private)", re.IGNORECASE)


def _check_cache_deception_url(url: str) -> list[str]:
    """Check URL patterns for cache deception indicators."""
    signals: list[str] = []
    path = urlparse(url).path.lower()

    if _CACHE_DECEPTION_PATTERN_RE.search(path):
        signals.append("dynamic_path_static_extension")

    has_dynamic_keyword = any(kw in path for kw in _DYNAMIC_PATH_KEYWORDS)
    has_static_extension = any(path.endswith(ext) for ext in _STATIC_EXTENSIONS)

    if has_dynamic_keyword and has_static_extension:
        signals.append("mixed_dynamic_static_path")

    if has_static_extension:
        signals.append("static_file_extension")

    if has_dynamic_keyword:
        signals.append("dynamic_content_path")

    if is_auth_flow_endpoint(url) and has_static_extension:
        signals.append("auth_endpoint_with_static_extension")

    return signals


def _check_cache_headers(response: dict[str, Any]) -> list[str]:
    """Check cache-related headers for deception indicators."""
    signals: list[str] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}

    cache_control = headers.get("cache-control", "")
    pragma = headers.get("pragma", "")
    vary = headers.get("vary", "")
    expires = headers.get("expires", "")

    if cache_control:
        if _PUBLIC_CACHE_RE.search(cache_control) and not _NO_CACHE_RE.search(cache_control):
            signals.append("public_cache_directive")

        if "s-maxage" in cache_control.lower():
            signals.append("shared_cache_max_age")

        max_age_match = re.search(r"max-age=(\d+)", cache_control, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age > 3600:
                signals.append("long_cache_max_age")

    if pragma.lower() == "no-cache":
        signals.append("pragma_no_cache")

    if vary:
        signals.append("vary_header_present")
        vary_lower = vary.lower()
        if "cookie" in vary_lower or "authorization" in vary_lower:
            signals.append("vary_on_auth_header")
    else:
        signals.append("missing_vary_header")

    if expires and expires.lower() not in ("0", "-1", "expires"):
        signals.append("expires_header_set")

    etag = headers.get("etag", "")
    if etag:
        signals.append("etag_present")

    return signals


def _check_authenticated_endpoint_context(url: str, response: dict[str, Any]) -> list[str]:
    """Check if a potentially cacheable response is from an authenticated endpoint."""
    signals: list[str] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    cache_control = headers.get("cache-control", "").lower()

    is_public_cacheable = "public" in cache_control or (
        "no-store" not in cache_control
        and "no-cache" not in cache_control
        and "private" not in cache_control
    )

    if is_auth_flow_endpoint(url) and is_public_cacheable:
        signals.append("auth_endpoint_publicly_cacheable")

    path = urlparse(url).path.lower()
    sensitive_paths = {
        "/account",
        "/profile",
        "/settings",
        "/payment",
        "/billing",
        "/admin",
        "/api/",
    }
    is_sensitive = any(kw in path for kw in sensitive_paths)

    if is_sensitive and is_public_cacheable:
        signals.append("sensitive_endpoint_publicly_cacheable")

    if is_sensitive and not any(h in headers for h in ("vary",)):
        signals.append("sensitive_endpoint_missing_vary")

    return signals


def _check_path_normalization(url: str) -> list[str]:
    """Check for path normalization inconsistencies."""
    signals: list[str] = []
    path = urlparse(url).path

    if ".." in path:
        signals.append("path_traversal_in_url")

    if "//" in path:
        signals.append("double_slash_in_path")

    if "%2e%2e" in path.lower():
        signals.append("encoded_path_traversal")

    if path != path.rstrip("/").rstrip("/") + "/" and path.endswith("/"):
        normalized = path.rstrip("/")
        if normalized:
            signals.append("trailing_slash_variation")

    return signals


def _calculate_severity(signals: list[str]) -> str:
    critical_indicators = {
        "auth_endpoint_publicly_cacheable",
        "sensitive_endpoint_publicly_cacheable",
    }
    medium_indicators = {
        "public_cache_directive",
        "long_cache_max_age",
        "missing_vary_header",
        "auth_endpoint_with_static_extension",
    }

    for signal in signals:
        if signal in critical_indicators:
            return "critical"
    for signal in signals:
        if signal in medium_indicators:
            return "medium"
    return "low"


def _calculate_risk_score(signals: list[str]) -> int:
    score = 0
    severity_scores: dict[str, int] = {
        "auth_endpoint_publicly_cacheable": 9,
        "sensitive_endpoint_publicly_cacheable": 8,
        "dynamic_path_static_extension": 7,
        "mixed_dynamic_static_path": 7,
        "sensitive_endpoint_missing_vary": 6,
        "public_cache_directive": 4,
        "long_cache_max_age": 3,
        "missing_vary_header": 3,
        "auth_endpoint_with_static_extension": 5,
        "shared_cache_max_age": 4,
        "path_traversal_in_url": 5,
        "double_slash_in_path": 3,
        "encoded_path_traversal": 5,
        "trailing_slash_variation": 2,
    }

    for signal in signals:
        if signal in severity_scores:
            score += severity_scores[signal]

    return min(score, 20)


def cache_deception_detector(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Detect web cache deception surfaces passively.

    Analyzes URLs and responses for:
    - Endpoints with static file extensions returning dynamic content
    - URL patterns mixing dynamic paths with static extensions
    - Missing Vary headers on mixed content responses
    - Public cache headers on authenticated endpoints
    - Cache key confusion indicators
    - Path normalization inconsistencies

    Args:
        urls: Set of URLs to analyze.
        responses: List of HTTP response dicts.
        limit: Maximum number of findings to return.

    Returns:
        List of cache deception findings sorted by risk score.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url in sorted(urls):
        if is_noise_url(url):
            continue

        signals = _check_cache_deception_url(url)
        signals.extend(_check_path_normalization(url))

        if not signals:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(signals)
        risk_score = _calculate_risk_score(signals)
        confidence = normalized_confidence(
            base=0.42,
            score=risk_score,
            signals=signals,
            cap=0.88,
        )

        title_parts: list[str] = []
        if "dynamic_path_static_extension" in signals:
            title_parts.append("Dynamic Path with Static Extension")
        if "mixed_dynamic_static_path" in signals:
            title_parts.append("Mixed Dynamic/Static Path Pattern")
        if "auth_endpoint_with_static_extension" in signals:
            title_parts.append("Auth Endpoint with Static Extension")
        if "path_traversal_in_url" in signals:
            title_parts.append("Path Traversal in URL")
        if "double_slash_in_path" in signals:
            title_parts.append("Double Slash in Path")

        title = "; ".join(title_parts) if title_parts else "Cache Deception Surface Detected"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": sorted(signals),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        signals: list[str] = []
        signals.extend(_check_cache_headers(response))
        signals.extend(_check_authenticated_endpoint_context(url, response))

        if not signals:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(signals)
        risk_score = _calculate_risk_score(signals)
        confidence = normalized_confidence(
            base=0.42,
            score=risk_score,
            signals=signals,
            cap=0.90,
        )

        title_parts: list[str] = []
        if "auth_endpoint_publicly_cacheable" in signals:
            title_parts.append("Auth Endpoint Publicly Cacheable")
        if "sensitive_endpoint_publicly_cacheable" in signals:
            title_parts.append("Sensitive Endpoint Publicly Cacheable")
        if "public_cache_directive" in signals:
            title_parts.append("Public Cache Directive")
        if "missing_vary_header" in signals:
            title_parts.append("Missing Vary Header")
        if "sensitive_endpoint_missing_vary" in signals:
            title_parts.append("Sensitive Endpoint Missing Vary")
        if "long_cache_max_age" in signals:
            title_parts.append("Long Cache Max-Age")

        title = "; ".join(title_parts) if title_parts else "Cache Deception Response Indicator"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": sorted(signals),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    findings.sort(key=lambda item: (-item["risk_score"], item["url"]))
    return findings[:limit]
