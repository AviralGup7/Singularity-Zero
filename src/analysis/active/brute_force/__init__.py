"""Brute force resistance probe for authentication endpoints (OWASP A07).

Detects authentication endpoints and tests for:
- Rate limiting on authentication endpoints
- Account lockout after failed attempts
- CAPTCHA presence after failed attempts
- Progressive delays between attempts
- IP-based blocking
- Username enumeration via different error messages
- Timing attacks (different response times for valid vs invalid usernames)
- Credential stuffing resistance

This package modularizes the brute force probe into separate files
for better maintainability and AI-agent editability.
"""

from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, ensure_endpoint_key

from ._constants import BRUTE_FORCE_PROBE_SPEC
from ._helpers import (
    check_account_lockout,
    check_captcha,
    check_credential_stuffing,
    check_ip_blocking,
    check_progressive_delays,
    check_rate_limiting,
    check_timing_attack,
    check_username_enumeration,
    detect_auth_headers,
    is_auth_endpoint,
    probe_confidence,
    probe_severity,
)

__all__ = [
    "brute_force_resistance_probe",
    "BRUTE_FORCE_PROBE_SPEC",
    "is_auth_endpoint",
    "probe_confidence",
    "probe_severity",
]


def brute_force_resistance_probe(
    priority_urls: list[str | dict[str, Any]],
    response_cache: Any,
    limit: int = 12,
    max_attempts: int = 20,
) -> list[dict[str, Any]]:
    """Probe authentication endpoints for brute force resistance weaknesses.

    Tests for rate limiting, account lockout, CAPTCHA, progressive delays,
    IP blocking, username enumeration, timing attacks, and credential stuffing.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url_item in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_item.get("url", "") if isinstance(url_item, dict) else url_item).strip()
        if not url:
            continue

        if not is_auth_endpoint(url):
            continue

        endpoint_key = (
            ensure_endpoint_key(url_item, url)
            if isinstance(url_item, dict)
            else endpoint_base_key(url)
        )
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        issues: list[str] = []
        evidence: dict[str, Any] = {}

        # Test 1: Rate limiting (Fix Audit #13: Short-circuit if well protected)
        rate_limit_result = check_rate_limiting(url, response_cache, max_attempts)
        evidence["rate_limiting"] = rate_limit_result

        is_well_protected = False
        if rate_limit_result["rate_limited"]:
            if rate_limit_result["attempts_before_limit"] <= 10:
                is_well_protected = True
            else:
                issues.append("weak_rate_limiting")
        else:
            issues.append("no_rate_limiting")

        if is_well_protected:
            # Endpoint is already rate-limited, no need to spray more requests
            # Just report any existing issues (unlikely if well protected)
            if not issues:
                continue  # Skip reporting if it's fine

        # Test 2: Account lockout
        lockout_result = check_account_lockout(url, response_cache, max_attempts)
        evidence["account_lockout"] = lockout_result
        if not lockout_result["locked_out"]:
            issues.append("no_account_lockout")

        # Test 3: CAPTCHA (Fix Audit #39: Only report if it's a known auth page)
        captcha_result = check_captcha(url, response_cache, max_attempts)
        evidence["captcha"] = captcha_result
        if not captcha_result["captcha_detected"]:
            # Report only if it's a likely high-traffic target
            if "weak_rate_limiting" in issues or "no_rate_limiting" in issues:
                issues.append("no_captcha")

        # ... (rest of tests) ...

        # Test 5: IP blocking (Fix Audit #39: High false positive rate)
        ip_result = check_ip_blocking(url, response_cache, max_attempts)
        evidence["ip_blocking"] = ip_result
        if not ip_result["ip_blocked"] and "no_rate_limiting" in issues:
            # Only report missing IP block if NO rate limiting at all is found
            issues.append("no_ip_blocking")

        # Test 6: Username enumeration
        enum_result = check_username_enumeration(url, response_cache)
        evidence["username_enumeration"] = enum_result
        if enum_result["enumeration_possible"]:
            issues.append("username_enumeration")

        # Test 7: Timing attacks
        timing_result = check_timing_attack(url, response_cache)
        evidence["timing_attack"] = timing_result
        if timing_result["timing_vulnerable"]:
            issues.append("timing_attack_vulnerable")

        # Test 8: Credential stuffing
        stuffing_result = check_credential_stuffing(url, response_cache, min(max_attempts, 5))
        evidence["credential_stuffing"] = stuffing_result
        if (
            not stuffing_result["stuffing_resistant"]
            and len(stuffing_result["successful_logins"]) > 0
        ):
            issues.append("credential_stuffing_vulnerable")

        # Test 9: Missing auth headers
        baseline_response = response_cache.get(url)
        header_result = detect_auth_headers(baseline_response)
        evidence["security_headers"] = header_result
        if len(header_result["missing_headers"]) >= 4:
            issues.append("missing_auth_headers")

        if not issues:
            continue

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "category": "brute_force_resistance",
                "title": f"Brute force resistance weaknesses: {url}",
                "severity": probe_severity(issues),
                "confidence": probe_confidence(issues),
                "score": {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.0}.get(
                    probe_severity(issues), 0.0
                ),
                "issues": sorted(issues),
                "evidence": evidence,
                "signals": sorted(issues),
            }
        )

    findings.sort(
        key=lambda item: (-item.get("confidence", 0), -item.get("score", 0), item.get("url", ""))
    )
    return findings[:limit]
