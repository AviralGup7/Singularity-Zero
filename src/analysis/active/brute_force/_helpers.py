"""Helper functions for brute force resistance probing."""

import json
import time
from typing import Any, cast

from src.analysis.helpers._probe_utils import (
    probe_confidence_from_map as _probe_confidence_from_map,
)
from src.analysis.helpers._probe_utils import (
    probe_severity_from_map as _probe_severity_from_map,
)
from src.analysis.passive.runtime import ResponseCache

from ._constants import (
    AUTH_ENDPOINT_PATTERNS,
    COMMON_PASSWORDS,
    COMMON_USERNAMES,
    INVALID_PASSWORD,
    INVALID_USERNAME,
    PROBE_CONFIDENCE,
    PROBE_SEVERITY,
)


def is_auth_endpoint(url: str) -> bool:
    """Check if a URL is an authentication endpoint."""
    path = str(url).lower()
    return any(pattern in path for pattern in AUTH_ENDPOINT_PATTERNS)


def probe_confidence(issues: list[str]) -> float:
    """Compute confidence score from detected issues."""
    return _probe_confidence_from_map(issues, PROBE_CONFIDENCE, cap=0.98)


def probe_severity(issues: list[str]) -> str:
    """Return the highest severity from detected issues."""
    return _probe_severity_from_map(issues, PROBE_SEVERITY)


def build_login_payload(url: str, username: str, password: str) -> str:
    """Build login payload based on URL patterns."""
    path = str(url).lower()
    if "json" in path or "api" in path:
        return json.dumps({"username": username, "password": password})
    return f"username={username}&password={password}"


def check_rate_limiting(
    url: str,
    response_cache: ResponseCache,
    max_attempts: int,
) -> dict[str, Any]:
    """Check for rate limiting on authentication endpoint."""
    rate_limited = False
    rate_limit_status_codes: list[int] = []
    rate_limit_headers: dict[str, str] = {}
    attempts_before_limit = 0
    evidence: list[str] = []

    for attempt in range(max_attempts):
        payload = build_login_payload(url, INVALID_USERNAME, INVALID_PASSWORD)
        response = response_cache.request(
            url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=payload,
        )
        if response is None:
            continue

        status = int(response.get("status_code") or 0)
        raw_headers: Any = response.get("headers") or {}
        headers: dict[str, str] = {
            str(key).lower(): str(value) for key, value in cast(dict[str, Any], raw_headers).items()
        }

        if status == 429:
            rate_limited = True
            rate_limit_status_codes.append(status)
            for header_name in (
                "x-ratelimit-limit",
                "x-ratelimit-remaining",
                "x-ratelimit-reset",
                "retry-after",
                "x-rate-limit-limit",
                "x-rate-limit-remaining",
                "x-rate-limit-reset",
            ):
                if header_name in headers:
                    rate_limit_headers[header_name] = headers[header_name]
            evidence.append(f"Rate limited after {attempt + 1} attempts (HTTP {status})")
            break

        if status == 403:
            body_lower = str(response.get("body_text", "")).lower()
            if "rate" in body_lower or "limit" in body_lower or "too many" in body_lower:
                rate_limited = True
                rate_limit_status_codes.append(status)
                evidence.append(f"Possible rate limit after {attempt + 1} attempts (HTTP {status})")
                break

        attempts_before_limit = attempt + 1

    return {
        "rate_limited": rate_limited,
        "rate_limit_status_codes": rate_limit_status_codes,
        "rate_limit_headers": rate_limit_headers,
        "attempts_before_limit": attempts_before_limit,
        "evidence": evidence,
    }


def check_account_lockout(
    url: str,
    response_cache: ResponseCache,
    max_attempts: int,
) -> dict[str, Any]:
    """Check for account lockout after failed attempts."""
    locked_out = False
    lockout_evidence: list[str] = []
    error_messages: list[str] = []
    status_codes: list[int] = []

    for attempt in range(max_attempts):
        payload = build_login_payload(url, INVALID_USERNAME, INVALID_PASSWORD)
        response = response_cache.request(
            url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=payload,
        )
        if response is None:
            continue

        status = int(response.get("status_code") or 0)
        status_codes.append(status)
        body_text = str(response.get("body_text", ""))
        body_lower = body_text.lower()

        error_indicators = [
            "account locked",
            "locked out",
            "too many attempts",
            "try again later",
            "temporarily locked",
            "account disabled",
            "maximum attempts",
            "lockout",
            "suspended",
        ]
        for indicator in error_indicators:
            if indicator in body_lower:
                locked_out = True
                lockout_evidence.append(
                    f"Account lockout detected after {attempt + 1} attempts: '{indicator}'"
                )
                break

        error_messages.append(body_lower[:200])

    return {
        "locked_out": locked_out,
        "lockout_evidence": lockout_evidence,
        "error_messages_sample": error_messages[:5],
        "status_codes": status_codes[:10],
    }


def check_captcha(
    url: str,
    response_cache: ResponseCache,
    max_attempts: int,
) -> dict[str, Any]:
    """Check for CAPTCHA presence after failed attempts."""
    captcha_detected = False
    captcha_type: str | None = None
    captcha_evidence: list[str] = []

    captcha_indicators = [
        ("recaptcha", "reCAPTCHA"),
        ("hcaptcha", "hCaptcha"),
        ("turnstile", "Cloudflare Turnstile"),
        ("captcha", "CAPTCHA"),
        ("g-recaptcha", "reCAPTCHA (widget)"),
        ("cf-turnstile", "Cloudflare Turnstile (widget)"),
        ("h-captcha", "hCaptcha (widget)"),
        ("challenge-platform", "Challenge Platform"),
        ("verify you are human", "Human Verification"),
        ("prove you are human", "Human Verification"),
    ]

    for attempt in range(min(max_attempts, 5)):
        payload = build_login_payload(url, INVALID_USERNAME, INVALID_PASSWORD)
        response = response_cache.request(
            url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=payload,
        )
        if response is None:
            continue

        body_text = str(response.get("body_text", "")).lower()
        headers = {
            str(key).lower(): str(value)
            for key, value in cast(dict[str, Any], response.get("headers") or {}).items()
        }

        for indicator, name in captcha_indicators:
            if indicator in body_text or indicator in headers.get("x-captcha-type", ""):
                captcha_detected = True
                captcha_type = name
                captcha_evidence.append(f"{name} detected after {attempt + 1} failed attempts")
                break

        if captcha_detected:
            break

    return {
        "captcha_detected": captcha_detected,
        "captcha_type": captcha_type,
        "captcha_evidence": captcha_evidence,
    }


def check_progressive_delays(
    url: str,
    response_cache: ResponseCache,
    max_attempts: int,
) -> dict[str, Any]:
    """Check for progressive delays between failed attempts."""
    response_times: list[float] = []
    progressive_delay_detected = False
    delay_evidence: list[str] = []

    for _attempt in range(min(max_attempts, 8)):
        payload = build_login_payload(url, INVALID_USERNAME, INVALID_PASSWORD)
        start_time = time.monotonic()
        response_cache.request(
            url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=payload,
        )
        elapsed_ms = (time.monotonic() - start_time) * 1000
        response_times.append(round(elapsed_ms, 1))

    if len(response_times) >= 4:
        first_half_avg = sum(response_times[: len(response_times) // 2]) / (
            len(response_times) // 2
        )
        second_half_avg = sum(response_times[len(response_times) // 2 :]) / (
            len(response_times) - len(response_times) // 2
        )
        if second_half_avg > first_half_avg * 1.5:
            progressive_delay_detected = True
            delay_evidence.append(
                f"Progressive delay detected: first half avg {first_half_avg:.1f}ms, "
                f"second half avg {second_half_avg:.1f}ms"
            )

    return {
        "progressive_delay_detected": progressive_delay_detected,
        "response_times_ms": response_times,
        "delay_evidence": delay_evidence,
    }


def check_ip_blocking(
    url: str,
    response_cache: ResponseCache,
    max_attempts: int,
) -> dict[str, Any]:
    """Check for IP-based blocking after failed attempts."""
    ip_blocked = False
    blocking_evidence: list[str] = []
    blocking_status_codes: list[int] = []

    for attempt in range(max_attempts):
        payload = build_login_payload(url, INVALID_USERNAME, INVALID_PASSWORD)
        response = response_cache.request(
            url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=payload,
        )
        if response is None:
            continue

        status = int(response.get("status_code") or 0)
        body_text = str(response.get("body_text", "")).lower()

        blocking_indicators = [
            "ip blocked",
            "ip banned",
            "blocked ip",
            "access denied",
            "forbidden",
            "your ip has been",
            "rate limit exceeded",
            "temporarily blocked",
            "permanently blocked",
        ]

        if status == 403 or status == 451:
            for indicator in blocking_indicators:
                if indicator in body_text:
                    ip_blocked = True
                    blocking_status_codes.append(status)
                    blocking_evidence.append(
                        f"IP blocking detected after {attempt + 1} attempts: "
                        f"HTTP {status} - '{indicator}'"
                    )
                    break

        if ip_blocked:
            break

    return {
        "ip_blocked": ip_blocked,
        "blocking_status_codes": blocking_status_codes,
        "blocking_evidence": blocking_evidence,
    }


def check_username_enumeration(
    url: str,
    response_cache: ResponseCache,
) -> dict[str, Any]:
    """Check for username enumeration via different error messages."""
    enumeration_possible = False
    enumeration_evidence: list[str] = []
    valid_user_responses: list[dict[str, Any]] = []
    invalid_user_responses: list[dict[str, Any]] = []

    for username in COMMON_USERNAMES[:3]:
        payload = build_login_payload(url, username, INVALID_PASSWORD)
        valid_response = response_cache.request(
            url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=payload,
        )
        invalid_response = response_cache.request(
            url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=build_login_payload(url, INVALID_USERNAME, INVALID_PASSWORD),
        )

        if valid_response and invalid_response:
            valid_body = str(valid_response.get("body_text", "")).lower()
            invalid_body = str(invalid_response.get("body_text", "")).lower()
            valid_status = int(valid_response.get("status_code") or 0)
            invalid_status = int(invalid_response.get("status_code") or 0)

            valid_user_responses.append(
                {"username": username, "status": valid_status, "body_snippet": valid_body[:100]}
            )
            invalid_user_responses.append(
                {
                    "username": INVALID_USERNAME,
                    "status": invalid_status,
                    "body_snippet": invalid_body[:100],
                }
            )

            if valid_status != invalid_status:
                enumeration_possible = True
                enumeration_evidence.append(
                    f"Different status codes: valid user '{username}' -> {valid_status}, "
                    f"invalid user -> {invalid_status}"
                )

            error_messages_differ = (
                ("invalid password" in valid_body and "user not found" in invalid_body)
                or ("incorrect password" in valid_body and "no account" in invalid_body)
                or ("wrong password" in valid_body and "does not exist" in invalid_body)
            )

            if error_messages_differ:
                enumeration_possible = True
                enumeration_evidence.append(
                    f"Different error messages for valid vs invalid username '{username}'"
                )

    return {
        "enumeration_possible": enumeration_possible,
        "enumeration_evidence": enumeration_evidence,
        "valid_user_responses": valid_user_responses,
        "invalid_user_responses": invalid_user_responses,
    }


def check_timing_attack(
    url: str,
    response_cache: ResponseCache,
    iterations: int = 5,
) -> dict[str, Any]:
    """Check for timing attack vulnerability."""
    timing_vulnerable = False
    timing_evidence: list[str] = []
    valid_user_times: list[float] = []
    invalid_user_times: list[float] = []

    for username in COMMON_USERNAMES[:2]:
        for _ in range(iterations):
            payload = build_login_payload(url, username, INVALID_PASSWORD)
            start = time.monotonic()
            response_cache.request(
                url,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=payload,
            )
            elapsed = (time.monotonic() - start) * 1000
            valid_user_times.append(round(elapsed, 2))

            start = time.monotonic()
            response_cache.request(
                url,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=build_login_payload(url, INVALID_USERNAME, INVALID_PASSWORD),
            )
            elapsed = (time.monotonic() - start) * 1000
            invalid_user_times.append(round(elapsed, 2))

    if valid_user_times and invalid_user_times:
        valid_avg = sum(valid_user_times) / len(valid_user_times)
        invalid_avg = sum(invalid_user_times) / len(invalid_user_times)
        time_diff = abs(valid_avg - invalid_avg)

        if time_diff > 50:
            timing_vulnerable = True
            timing_evidence.append(
                f"Timing difference detected: valid user avg {valid_avg:.2f}ms, "
                f"invalid user avg {invalid_avg:.2f}ms (diff: {time_diff:.2f}ms)"
            )

    return {
        "timing_vulnerable": timing_vulnerable,
        "timing_evidence": timing_evidence,
        "valid_user_avg_ms": round(sum(valid_user_times) / max(len(valid_user_times), 1), 2),
        "invalid_user_avg_ms": round(sum(invalid_user_times) / max(len(invalid_user_times), 1), 2),
    }


def check_credential_stuffing(
    url: str,
    response_cache: ResponseCache,
    max_attempts: int,
) -> dict[str, Any]:
    """Check for credential stuffing resistance."""
    stuffing_resistant = False
    stuffing_evidence: list[str] = []
    successful_logins: list[dict[str, Any]] = []

    for idx, (username, password) in enumerate(zip(COMMON_USERNAMES, COMMON_PASSWORDS)):
        if idx >= max_attempts:
            break
        payload = build_login_payload(url, username, password)
        response = response_cache.request(
            url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=payload,
        )
        if response is None:
            continue

        status = int(response.get("status_code") or 0)
        body_text = str(response.get("body_text", "")).lower()
        headers = {
            str(key).lower(): str(value)
            for key, value in cast(dict[str, Any], response.get("headers") or {}).items()
        }

        success_indicators = [
            "welcome",
            "dashboard",
            "logout",
            "signout",
            "access_token",
            "refresh_token",
            "session_id",
            "redirect",
            "home",
            "profile",
        ]
        is_success = (
            status in (200, 301, 302, 303, 307, 308)
            and any(indicator in body_text for indicator in success_indicators)
        ) or ("authorization" in headers or "set-cookie" in headers)

        if is_success and status < 400:
            successful_logins.append(
                {"username": username, "status": status, "headers": list(headers.keys())}
            )

        if status == 429 or status == 403:
            stuffing_resistant = True
            stuffing_evidence.append(
                f"Rate limited after {idx + 1} credential attempts (HTTP {status})"
            )
            break

    if not stuffing_resistant and len(successful_logins) == 0:
        stuffing_evidence.append(
            f"No successful logins from {min(len(COMMON_USERNAMES), max_attempts)} common credential pairs"
        )

    return {
        "stuffing_resistant": stuffing_resistant,
        "successful_logins": successful_logins,
        "stuffing_evidence": stuffing_evidence,
    }


def detect_auth_headers(response: dict[str, Any] | None) -> dict[str, Any]:
    """Detect missing security headers on auth responses."""
    if response is None:
        return {"missing_headers": [], "present_headers": []}

    headers = {
        str(key).lower(): str(value)
        for key, value in cast(dict[str, Any], response.get("headers") or {}).items()
    }

    security_headers = [
        "x-content-type-options",
        "x-frame-options",
        "strict-transport-security",
        "content-security-policy",
        "x-xss-protection",
        "cache-control",
        "pragma",
    ]

    present = [h for h in security_headers if h in headers]
    missing = [h for h in security_headers if h not in headers]

    return {"present_headers": present, "missing_headers": missing}
