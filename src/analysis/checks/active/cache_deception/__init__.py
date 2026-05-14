"""Cache Deception Probe (Active).

Tests for web cache deception vulnerabilities by requesting sensitive endpoints
with static file extensions and path normalization tricks, then checking if
responses are served with cache-friendly headers despite containing user-specific
data.

This package modularizes the cache deception probe into separate files
for better maintainability and AI-agent editability.
"""

import logging
from typing import Any

from src.analysis.helpers import endpoint_base_key, normalize_headers
from src.analysis.helpers.scoring import normalized_confidence


from ._constants import CHECK_SPEC
from ._helpers import (
    build_finding,
    build_path_traversal_urls,
    build_static_extension_urls,
    has_cacheable_response,
    is_sensitive_endpoint,
    response_contains_sensitive_data,
    safe_request,
)
logger = logging.getLogger(__name__)

__all__ = ["cache_deception_probe", "CHECK_SPEC"]


def cache_deception_probe(
    priority_urls: list[dict[str, Any]] | None = None,
    response_cache: Any = None,
    limit: int = 15,
) -> list[dict[str, Any]]:
    """Test for web cache deception vulnerabilities."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    if not priority_urls:
        return findings

    endpoints_to_test: list[dict[str, Any]] = []
    for item in priority_urls[: limit * 3]:
        url = str(item.get("url", "")).strip()
        if not url or not url.startswith(("http://", "https://")):
            continue
        resp = None
        if response_cache is not None:
            try:
                resp = response_cache.get(url)
            except Exception:
                logger.warning("Cache lookup failed for %s", url)
                pass
        if not is_sensitive_endpoint(url, resp):
            continue
        endpoints_to_test.append({"url": url, "response": resp})
        if len(endpoints_to_test) >= limit:
            break

    for endpoint in endpoints_to_test:
        url = endpoint["url"]
        original_resp = endpoint.get("response")

        base_key = endpoint_base_key(url)
        if base_key in seen:
            continue
        seen.add(base_key)

        original_headers: dict[str, str] = {}
        auth_headers: dict[str, str] = {}
        if original_resp:
            original_headers = normalize_headers(original_resp)
            for key, val in original_headers.items():
                if key.lower() in {
                    "authorization",
                    "x-auth-token",
                    "x-api-key",
                    "cookie",
                    "x-csrf-token",
                    "x-request-id",
                    "x-session-id",
                    "bearer",
                }:
                    auth_headers[key] = val

        test_urls_static = build_static_extension_urls(url)
        test_urls_traversal = build_path_traversal_urls(url)
        all_test_urls = test_urls_static + test_urls_traversal

        findings_for_endpoint: list[dict[str, Any]] = []

        for test_url in all_test_urls:
            request_headers = {"Accept": "*/*"}
            if auth_headers:
                request_headers.update(auth_headers)

            result = safe_request(test_url, method="GET", headers=request_headers, timeout=8)
            if result.get("status", 0) == 0:
                continue

            test_status = result.get("status", 0)
            test_headers = result.get("headers", {})
            test_body = result.get("body", "")

            if test_status in (404, 410, 503):
                continue

            is_cacheable, cache_signals = has_cacheable_response(test_headers)
            has_sensitive, sensitive_signals = response_contains_sensitive_data(test_body)

            if not is_cacheable:
                continue

            variant_type = "static_extension" if test_url in test_urls_static else "path_traversal"
            signals = cache_signals + sensitive_signals
            signals.append(f"variant_type:{variant_type}")
            signals.append(f"test_url:{test_url}")

            if has_sensitive and is_cacheable:
                severity = "high"
                title = "Cached sensitive response via cache deception"
            elif is_cacheable and variant_type == "path_traversal":
                severity = "medium"
                title = "Path normalization bypass with cacheable response"
            else:
                severity = "low"
                title = "Potential cache deception surface"

            if has_sensitive:
                severity = "high"
                title = "Cached sensitive response via cache deception"

            evidence = {
                "test_url": test_url,
                "original_url": url,
                "variant_type": variant_type,
                "status_code": test_status,
                "cache_signals": cache_signals,
                "sensitive_signals": sensitive_signals[:10] if has_sensitive else [],
                "cacheable": is_cacheable,
                "sensitive_data": has_sensitive,
                "response_length": result.get("body_length", 0),
            }

            confidence = normalized_confidence(
                base=0.40 if severity == "low" else 0.60 if severity == "medium" else 0.75,
                score=8 if severity == "high" else 5 if severity == "medium" else 2,
                signals=signals,
            )

            explanation = (
                f"Test URL {test_url} returned a cacheable response (status {test_status}). "
                f"Variant type: {variant_type}. "
                f"Cache indicators: {', '.join(cache_signals[:5])}. "
                f"{'Contains sensitive data indicators.' if has_sensitive else 'No sensitive data detected in body.'} "
                f"This endpoint may be vulnerable to web cache deception attacks."
            )

            findings_for_endpoint.append(
                build_finding(
                    url=test_url,
                    status_code=test_status,
                    category="cache_deception",
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    signals=signals,
                    evidence=evidence,
                    explanation=explanation,
                )
            )

        if findings_for_endpoint:
            findings_for_endpoint.sort(
                key=lambda f: (
                    {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                        f["severity"], 5
                    ),
                    -f["confidence"],
                )
            )
            findings.extend(findings_for_endpoint[:5])

    # Check for unauthenticated cacheable responses
    unauth_findings: list[dict[str, Any]] = []
    for endpoint in endpoints_to_test[: limit // 2]:
        url = endpoint["url"]
        original_resp = endpoint.get("response")
        if not original_resp:
            continue
        original_headers = normalize_headers(original_resp)
        original_body = original_resp.get("body_text") or original_resp.get("body") or ""
        has_auth = any(
            k.lower()
            in {
                "authorization",
                "x-auth-token",
                "x-api-key",
                "cookie",
                "x-csrf-token",
                "x-request-id",
                "x-session-id",
                "bearer",
            }
            for k in original_headers
        )
        if not has_auth:
            continue
        is_cacheable_orig, cache_signals_orig = has_cacheable_response(original_headers)
        if not is_cacheable_orig:
            continue
        has_sensitive_orig, sensitive_signals_orig = response_contains_sensitive_data(original_body)
        if not has_sensitive_orig:
            continue
        no_auth_result = safe_request(url, method="GET", headers={"Accept": "*/*"}, timeout=8)
        if no_auth_result.get("status", 0) == 0:
            continue
        no_auth_cacheable, no_auth_cache_signals = has_cacheable_response(
            no_auth_result.get("headers", {})
        )
        if no_auth_cacheable:
            no_auth_sensitive, no_auth_sensitive_signals = response_contains_sensitive_data(
                no_auth_result.get("body", "")
            )
            if no_auth_sensitive:
                unauth_findings.append(
                    build_finding(
                        url=url,
                        status_code=no_auth_result.get("status"),
                        category="cache_deception",
                        title="Authenticated endpoint cacheable without auth",
                        severity="high",
                        confidence=0.80,
                        signals=cache_signals_orig
                        + no_auth_sensitive_signals
                        + ["unauthenticated_cacheable"],
                        evidence={
                            "original_url": url,
                            "original_status": original_resp.get("status_code"),
                            "no_auth_status": no_auth_result.get("status"),
                            "cache_signals": cache_signals_orig,
                            "sensitive_signals": no_auth_sensitive_signals[:10],
                        },
                        explanation=(
                            f"Endpoint {url} returns cacheable sensitive data even without authentication. "
                            f"This indicates a potential cache deception vulnerability where authenticated "
                            f"content may be served to unauthenticated users."
                        ),
                    )
                )

    findings.extend(unauth_findings)
    findings.sort(
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f["severity"], 5),
            -f["confidence"],
            f["url"],
        )
    )
    return findings[:limit]
