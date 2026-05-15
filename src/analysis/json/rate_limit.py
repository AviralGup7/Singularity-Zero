"""Rate limit signal analysis for JSON responses.

Contains functions for detecting missing rate limit headers, zero limits,
429 responses, retry-after values, body-based rate limit indicators,
inconsistent rate limiting across related endpoints, and rate limit bypass patterns.
Extracted from json_analysis.py for better separation of concerns.
"""

import logging
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature

logger = logging.getLogger(__name__)


def rate_limit_signal_analyzer(
    responses: list[dict[str, Any]], bulk_findings: list[dict[str, Any]], limit: int = 60
) -> list[dict[str, Any]]:
    """Analyze responses for rate limiting signals and misconfigurations.

    Detects missing rate limit headers, zero limits, 429 responses,
    retry-after values, body-based rate limit indicators, inconsistent
    rate limiting across related endpoints, and rate limit bypass patterns.
    """
    bulk_urls = {item.get("url", "") for item in bulk_findings}
    findings: list[dict[str, Any]] = []
    rate_limit_headers = {
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-ratelimit-requests",
        "x-ratelimit-used",
        "retry-after",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "x-rate-limit-limit",
        "x-rate-limit-remaining",
        "x-rate-limit-reset",
    }
    rate_limit_body_indicators = [
        "rate limit",
        "too many requests",
        "throttl",
        "slow down",
        "try again later",
        "quota exceeded",
        "rate_limited",
        "rateLimit",
        "request_limit",
        "max_requests",
        "api_limit",
    ]
    # Track rate limit patterns across endpoints for inconsistency detection
    endpoint_rate_limit_patterns: dict[str, list[str]] = {}

    for response in responses:
        url = str(response.get("url", "")).strip()
        headers = {
            str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()
        }
        endpoint_type = classify_endpoint(url)
        content_type = str(response.get("content_type", "")).lower()
        status_code = int(response.get("status_code") or 0)
        body_text = str(response.get("body_text", "")).lower()
        if endpoint_type != "API" and url not in bulk_urls and "json" not in content_type:
            continue
        issues = []
        evidence_level = "none"
        # Check for rate limit headers present
        present_rl_headers = [h for h in headers if h in rate_limit_headers]
        # Check for 429 Too Many Requests
        if status_code == 429:
            issues.append("rate_limit_429_response")
            evidence_level = "confirmed"
            if "retry-after" in headers:
                try:
                    retry_seconds = int(headers["retry-after"])
                    if retry_seconds > 60:
                        issues.append("extended_retry_period")
                    evidence_level = "confirmed_with_retry"
                except (ValueError, TypeError) as exc:
                    logger.debug("Ignored: %s", exc)
        # Check for zero limit header (misconfiguration)
        if headers.get("x-ratelimit-limit") == "0" or headers.get("ratelimit-limit") == "0":
            issues.append("zero_limit_header")
            if evidence_level == "none":
                evidence_level = "header_only"
        # Check for missing rate limit signals on API endpoints
        if not present_rl_headers and endpoint_type == "API":
            issues.append("missing_rate_limit_signals")
            if evidence_level == "none":
                evidence_level = "header_only"
        # Check for rate limit indicators in response body
        if any(indicator in body_text for indicator in rate_limit_body_indicators):
            issues.append("body_rate_limit_indicator")
            if evidence_level in ("none", "header_only"):
                evidence_level = "body_signal"
        # Check for inconsistent rate limiting (some headers present, some missing)
        if present_rl_headers:
            has_limit = any("limit" in h for h in present_rl_headers)
            has_remaining = any("remaining" in h for h in present_rl_headers)
            has_reset = any("reset" in h for h in present_rl_headers)
            if has_limit and not has_remaining:
                issues.append("missing_remaining_header")
            if has_limit and not has_reset:
                issues.append("missing_reset_header")
        # Check for rate limit bypass via IP headers
        ip_headers = {"x-forwarded-for", "x-real-ip", "x-client-ip", "x-originating-ip"}
        if any(h in headers for h in ip_headers) and not present_rl_headers:
            issues.append("potential_ip_based_bypass")
        # Check for unusually high rate limits (potential misconfiguration)
        for limit_header in ("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit"):
            if limit_header in headers:
                try:
                    limit_value = int(headers[limit_header])
                    if limit_value > 10000:
                        issues.append(f"unusually_high_rate_limit:{limit_value}")
                except (ValueError, TypeError) as exc:
                    logger.debug("Ignored: %s", exc)
        # Track patterns for cross-endpoint analysis
        if present_rl_headers:
            endpoint_base = endpoint_base_key(url)
            endpoint_rate_limit_patterns.setdefault(endpoint_base, []).extend(present_rl_headers)

        if issues:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": endpoint_type,
                    "status_code": status_code,
                    "issues": issues,
                    "observed_headers": sorted(present_rl_headers),
                    "evidence_level": evidence_level,
                    "retry_after_seconds": headers.get("retry-after"),
                }
            )

    # Add cross-endpoint inconsistency findings
    if len(endpoint_rate_limit_patterns) >= 2:
        # Check if some endpoints have rate limits while others don't
        all_endpoint_bases = set()
        for response in responses:
            url = str(response.get("url", "")).strip()
            if url:
                all_endpoint_bases.add(endpoint_base_key(url))

        endpoints_without_rl = all_endpoint_bases - set(endpoint_rate_limit_patterns.keys())
        if endpoints_without_rl and endpoint_rate_limit_patterns:
            findings.append(
                {
                    "url": "cross-endpoint",
                    "endpoint_key": "cross-endpoint-rate-limit",
                    "endpoint_base_key": "cross-endpoint",
                    "endpoint_type": "API",
                    "status_code": 0,
                    "issues": [
                        "inconsistent_rate_limiting",
                        f"endpoints_with_rl:{len(endpoint_rate_limit_patterns)}",
                        f"endpoints_without_rl:{len(endpoints_without_rl)}",
                    ],
                    "observed_headers": [],
                    "evidence_level": "body_signal",
                    "retry_after_seconds": None,
                    "cross_endpoint_analysis": True,
                    "endpoints_with_rate_limits": sorted(endpoint_rate_limit_patterns.keys())[:10],
                    "endpoints_without_rate_limits": sorted(endpoints_without_rl)[:10],
                }
            )

    findings.sort(
        key=lambda item: (
            0 if item["evidence_level"] in ("confirmed", "confirmed_with_retry") else 1,
            -len(item["issues"]),
            item["url"],
        )
    )
    return findings[:limit]
