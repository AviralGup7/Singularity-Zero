"""CSRF active probe."""

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.analysis._core.http_request import _safe_request
from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache

from ._confidence import probe_confidence, probe_severity

CSRF_PAYLOADS = [
    ("empty_token", {"X-CSRF-Token": "", "X-CSRFToken": "", "X-XSRF-Token": ""}),
    ("missing_token", {}),
    ("invalid_token", {"X-CSRF-Token": "invalid_csrf_token_12345"}),
    ("null_token", {"X-CSRF-Token": "null"}),
    ("undefined_token", {"X-CSRF-Token": "undefined"}),
]

CSRF_BYPASS_HEADERS = [
    ("origin_null", {"Origin": "null"}),
    ("origin_evil", {"Origin": "https://evil.com"}),
    ("referer_evil", {"Referer": "https://evil.com/csrf"}),
    ("origin_referer_mixed", {"Origin": "https://evil.com", "Referer": "https://evil.com/csrf"}),
]

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

STATE_CHANGING_PATH_HINTS = {
    "/login",
    "/logout",
    "/signin",
    "/signout",
    "/signup",
    "/register",
    "/update",
    "/edit",
    "/modify",
    "/change",
    "/save",
    "/create",
    "/delete",
    "/remove",
    "/destroy",
    "/add",
    "/set",
    "/reset",
    "/password",
    "/email",
    "/profile",
    "/account",
    "/settings",
    "/transfer",
    "/payment",
    "/checkout",
    "/order",
    "/purchase",
    "/subscribe",
    "/unsubscribe",
    "/follow",
    "/unfollow",
    "/like",
    "/comment",
    "/post",
    "/upload",
    "/import",
    "/export",
    "/activate",
    "/deactivate",
    "/enable",
    "/disable",
    "/approve",
    "/reject",
    "/grant",
    "/revoke",
    "/admin",
    "/user",
    "/role",
    "/permission",
}

CSRF_PARAM_NAMES = {
    "csrf_token",
    "csrftoken",
    "csrf",
    "xsrf_token",
    "xsrftoken",
    "authenticity_token",
    "_token",
    "token",
}

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

COOKIE_SAMESITE_RE = re.compile(r"(?i)(?:^|;\s*)samesite\s*=", re.MULTILINE)
COOKIE_SECURE_RE = re.compile(r"(?i)(?:^|;\s*)secure(?:\s|$|;)", re.MULTILINE)
COOKIE_HTTPONLY_RE = re.compile(r"(?i)(?:^|;\s*)httponly(?:\s|$|;)", re.MULTILINE)
CSRF_TOKEN_VALUE_RE = re.compile(r"[a-f0-9]{20,}", re.IGNORECASE)


def _is_state_changing_endpoint(url: str) -> bool:
    lowered = url.lower()
    return any(hint in lowered for hint in STATE_CHANGING_PATH_HINTS)


def _extract_csrf_tokens(response: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    body = str(response.get("body_text") or response.get("body") or "")
    for match in CSRF_TOKEN_VALUE_RE.finditer(body):
        val = match.group(0)
        if val not in tokens:
            tokens.append(val)
    return tokens


def _check_cookie_security(headers: dict[str, Any]) -> dict[str, Any]:
    set_cookie_headers = []
    for key, val in headers.items():
        if key.lower() == "set-cookie":
            set_cookie_headers.append(val)
    if isinstance(headers.get("set-cookie"), list):
        set_cookie_headers = headers["set-cookie"]
    elif isinstance(headers.get("set-cookie"), str):
        set_cookie_headers = [headers["set-cookie"]]

    issues: list[str] = []
    for cookie_str in set_cookie_headers:
        if not COOKIE_SECURE_RE.search(cookie_str):
            issues.append("cookie_missing_secure")
        if not COOKIE_HTTPONLY_RE.search(cookie_str):
            issues.append("cookie_missing_httponly")
        if not COOKIE_SAMESITE_RE.search(cookie_str):
            issues.append("cookie_missing_samesite")
        elif re.search(r"(?i)samesite\s*=\s*none", cookie_str):
            issues.append("cookie_samesite_none")
    return {"issues": issues, "cookies_tested": len(set_cookie_headers)}


def _detect_get_state_change(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for url_entry in priority_urls:
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url or not url.startswith(("http://", "https://")):
            continue
        parsed = urlparse(url)
        if not _is_state_changing_endpoint(url):
            continue
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        state_params = [
            (i, k)
            for i, (k, v) in enumerate(query_pairs)
            if k.lower()
            in {
                "action",
                "do",
                "op",
                "cmd",
                "command",
                "task",
                "func",
                "delete",
                "remove",
                "update",
                "create",
                "set",
                "change",
                "password",
                "email",
                "role",
                "status",
            }
        ]
        if not state_params:
            continue
        endpoint_key = endpoint_signature(url)
        issues: list[str] = ["get_based_state_change"]
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "issues": issues,
                "probes": [
                    {"parameter": k, "issue": "get_based_state_change"} for _, k in state_params[:3]
                ],
                "confidence": probe_confidence(issues),
                "severity": probe_severity(issues),
            }
        )
    return findings


def csrf_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test endpoints for CSRF vulnerabilities actively.

    Sends requests without CSRF tokens to state-changing endpoints,
    tests with empty/invalid CSRF token headers, checks SameSite cookie
    behavior, and tests for CSRF header bypass via Origin/Referer manipulation.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of CSRF findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    findings.extend(_detect_get_state_change(priority_urls, response_cache))

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url or not url.startswith(("http://", "https://")):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        if not _is_state_changing_endpoint(url):
            continue

        original_resp = response_cache.get(url)
        if not original_resp:
            original_resp = _safe_request(url, timeout=8)
        if not original_resp or original_resp.get("status") in (404, 405, 410, 503):
            continue

        original_status = original_resp.get("status", 0)
        original_body = str(original_resp.get("body") or original_resp.get("body_text") or "")
        original_headers = original_resp.get("headers", {})

        cookie_result = _check_cookie_security(original_headers)
        cookie_issues = cookie_result.get("issues", [])

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        csrf_tokens = _extract_csrf_tokens(original_resp)

        for payload_name, csrf_headers in CSRF_PAYLOADS:
            if len(url_probes) >= 3:
                break
            test_headers = dict(csrf_headers)
            for k, v in original_headers.items():
                if k.lower() in ("authorization", "cookie", "x-requested-with"):
                    test_headers[k] = v

            method = "POST"
            body_bytes = b"csrf_test=1"
            test_headers["Content-Type"] = "application/x-www-form-urlencoded"

            response = _safe_request(
                url, method=method, headers=test_headers, body=body_bytes, timeout=10
            )
            if not response:
                continue

            status = response.get("status", 0)
            body = str(response.get("body") or "")

            issues_for_hit: list[str] = []

            if status == 200 and original_status in (200, 201, 204):
                if (
                    len(body) > 50
                    and abs(len(body) - len(original_body)) < len(original_body) * 0.3
                ):
                    issues_for_hit.append("csrf_no_token_accepted")
            elif status in (200, 201, 204) and original_status in (400, 401, 403):
                issues_for_hit.append("csrf_bypassed_error_status")
            elif status == 200 and original_status == 0:
                issues_for_hit.append("csrf_no_token_accepted")

            if issues_for_hit:
                url_issues.extend(issues_for_hit)
                url_probes.append(
                    {
                        "payload_type": payload_name,
                        "status_code": status,
                        "original_status": original_status,
                        "issues": issues_for_hit,
                    }
                )

        if not url_probes and cookie_issues:
            url_issues.extend(cookie_issues[:3])
            url_probes.append(
                {
                    "payload_type": "cookie_security",
                    "issues": cookie_issues[:3],
                }
            )

        for bypass_name, bypass_headers in CSRF_BYPASS_HEADERS:
            if len(url_probes) >= 3:
                break
            test_headers = dict(bypass_headers)
            test_headers["Content-Type"] = "application/x-www-form-urlencoded"
            for k, v in original_headers.items():
                if k.lower() in ("authorization", "cookie"):
                    test_headers[k] = v

            response = _safe_request(
                url, method="POST", headers=test_headers, body=b"csrf_test=1", timeout=10
            )
            if not response:
                continue

            status = response.get("status", 0)
            issues_for_hit = []

            if status in (200, 201, 204):
                bypass_origin = bypass_headers.get("Origin", "")
                if bypass_origin and bypass_origin != "null":
                    issues_for_hit.append("csrf_origin_bypass")
                elif bypass_origin == "null":
                    issues_for_hit.append("csrf_null_origin_accepted")
                elif "Referer" in bypass_headers:
                    issues_for_hit.append("csrf_referer_bypass")

            if issues_for_hit:
                url_issues.extend(issues_for_hit)
                url_probes.append(
                    {
                        "payload_type": bypass_name,
                        "status_code": status,
                        "issues": issues_for_hit,
                    }
                )

        if csrf_tokens and len(csrf_tokens) >= 2:
            if csrf_tokens[0] == csrf_tokens[1]:
                url_issues.append("csrf_token_predictable")
                url_probes.append(
                    {
                        "payload_type": "token_predictability",
                        "issues": ["csrf_token_predictable"],
                    }
                )

        if url_probes:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": url_issues,
                    "probes": url_probes,
                    "confidence": probe_confidence(url_issues),
                    "severity": probe_severity(url_issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]
