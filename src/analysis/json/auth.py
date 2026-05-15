"""Authentication-related analysis for JSON responses.

Contains functions for unauthenticated access checks, session reuse detection,
logout invalidation, and multi-endpoint auth consistency.
Extracted from json_analysis.py for better separation of concerns.
"""

import re
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    meaningful_query_pairs,
)
from src.analysis.json.support import (
    SESSION_PARAM_NAMES,
)
from src.analysis.json.support import (
    find_related_authenticated_endpoints as _find_related_authenticated_endpoints,
)
from src.analysis.json.support import (
    is_low_risk_read_candidate as _is_low_risk_read_candidate,
)
from src.analysis.json.support import (
    parse_json_payload as _parse_json_payload,
)
from src.analysis.json.support import (
    response_has_auth_signals as _response_has_auth_signals,
)
from src.analysis.passive.patterns import UUID_RE
from src.analysis.passive.runtime import extract_key_fields, normalize_compare_text


def session_reuse_detection(
    urls: set[str], responses: list[dict[str, Any]], limit: int = 60
) -> list[dict[str, Any]]:
    """Detect session tokens reused across different endpoints and flows."""
    token_usage: dict[str, dict[str, Any]] = {}
    for url in sorted(urls):
        for key, value in meaningful_query_pairs(url):
            if key not in SESSION_PARAM_NAMES or not value:
                continue
            entry = token_usage.setdefault(
                value,
                {
                    "parameters": set(),
                    "urls": set(),
                    "endpoint_types": set(),
                    "hosts": set(),
                },
            )
            entry["parameters"].add(key)
            entry["urls"].add(url)
            entry["endpoint_types"].add(classify_endpoint(url))
            entry["hosts"].add(urlparse(url).netloc.lower())
    for response in responses:
        body = response.get("body_text") or ""
        url = str(response.get("url", "")).strip()
        for match in re.finditer(
            r'"(?:access_token|refresh_token|id_token|session|jwt)"\s*:\s*"([^"]{8,})"', body
        ):
            value = match.group(1)
            entry = token_usage.setdefault(
                value,
                {
                    "parameters": set(),
                    "urls": set(),
                    "endpoint_types": set(),
                    "hosts": set(),
                },
            )
            entry["parameters"].add("response_body")
            entry["urls"].add(url)
            entry["endpoint_types"].add(classify_endpoint(url))
            entry["hosts"].add(urlparse(url).netloc.lower())

    findings: list[dict[str, Any]] = []
    for token_value, entry in token_usage.items():
        if len(entry["urls"]) < 2:
            continue
        urls_list = sorted(entry["urls"])
        findings.append(
            {
                "url": urls_list[0],
                "endpoint_key": endpoint_signature(urls_list[0]),
                "endpoint_base_key": endpoint_base_key(urls_list[0]),
                "token_shape": "uuid_like" if UUID_RE.search(token_value) else "opaque",
                "reuse_count": len(urls_list),
                "parameters": sorted(entry["parameters"]),
                "endpoint_types": sorted(entry["endpoint_types"]),
                "hosts": sorted(entry["hosts"]),
                "urls": urls_list[:8],
                "cross_flow_reuse": len(entry["endpoint_types"]) >= 2,
            }
        )
    findings.sort(key=lambda item: (-item["reuse_count"], item["url"]))
    return findings[:limit]


def logout_invalidation_check(
    priority_urls: list[str], response_cache: Any, limit: int = 20
) -> list[dict[str, Any]]:
    """Check whether sessions remain valid after logout."""
    findings: list[dict[str, Any]] = []
    logout_urls = [
        url
        for url in priority_urls
        if any(
            token in url.lower()
            for token in ("/logout", "/signout", "/session/end", "/session/logout")
        )
    ]
    if not logout_urls:
        return findings
    for logout_url in logout_urls[:limit]:
        logout_response = response_cache.get(logout_url)
        if not logout_response:
            continue
        related = _find_related_authenticated_endpoints(priority_urls, logout_url)
        for candidate in related[:3]:
            baseline = response_cache.get(candidate)
            post_logout = response_cache.request(candidate, headers={"Cache-Control": "no-cache"})
            if not baseline or not post_logout:
                continue
            similarity = round(
                SequenceMatcher(
                    None,
                    normalize_compare_text(baseline.get("body_text") or ""),
                    normalize_compare_text(post_logout.get("body_text") or ""),
                ).ratio(),
                3,
            )
            if int(post_logout.get("status_code") or 0) >= 400 and similarity < 0.96:
                continue
            findings.append(
                {
                    "url": candidate,
                    "logout_url": logout_url,
                    "endpoint_key": endpoint_signature(candidate),
                    "endpoint_base_key": endpoint_base_key(candidate),
                    "baseline_status": baseline.get("status_code"),
                    "post_logout_status": post_logout.get("status_code"),
                    "body_similarity": similarity,
                    "session_still_valid": int(post_logout.get("status_code") or 0) < 400
                    and similarity >= 0.9,
                }
            )
            if len(findings) >= limit:
                return findings
    return findings


def multi_endpoint_auth_consistency_check(
    responses: list[dict[str, Any]], limit: int = 50
) -> list[dict[str, Any]]:
    """Check for mixed authentication enforcement across endpoints on the same host."""
    findings: list[dict[str, Any]] = []
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        if not _is_low_risk_read_candidate(url):
            continue
        host = urlparse(url).netloc.lower()
        endpoint_type = classify_endpoint(url)
        grouped.setdefault((host, endpoint_type), []).append(response)

    for (host, endpoint_type), items in grouped.items():
        restricted = []
        accessible = []
        for response in items:
            status = int(response.get("status_code") or 0)
            url = str(response.get("url", "")).strip()
            if status in {401, 403}:
                restricted.append(url)
            elif status < 400 and _response_has_auth_signals(response):
                accessible.append(url)
        if restricted and accessible:
            findings.append(
                {
                    "url": accessible[0],
                    "host": host,
                    "endpoint_type": endpoint_type,
                    "restricted_count": len(restricted),
                    "accessible_auth_count": len(accessible),
                    "restricted_examples": restricted[:4],
                    "accessible_examples": accessible[:4],
                    "signals": ["mixed_auth_enforcement"],
                }
            )
    findings.sort(
        key=lambda item: (-(item["restricted_count"] + item["accessible_auth_count"]), item["host"])
    )
    return findings[:limit]


def unauth_access_check(
    priority_urls: list[str], response_cache: Any, limit: int = 24
) -> list[dict[str, Any]]:
    """Test whether endpoints are accessible without authentication."""
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        if len(findings) >= limit:
            break
        if not _is_low_risk_read_candidate(url):
            continue
        original = response_cache.get(url)
        if not original:
            continue
        endpoint_type = classify_endpoint(url)
        if endpoint_type not in {"API", "GENERAL"}:
            continue

        # Test 1: Remove all auth headers
        unauth = response_cache.request(
            url, headers={"Cookie": "", "Authorization": "", "Cache-Control": "no-cache"}
        )
        if unauth and _check_auth_bypass(original, unauth, url):
            findings.append(
                _build_auth_bypass_finding(url, original, unauth, "stripped_auth_headers")
            )
            continue

        # Test 2: Method override bypass
        if original.get("status_code") in {401, 403, 405}:
            method_override = response_cache.request(
                url,
                method="POST",
                headers={
                    "X-HTTP-Method-Override": "GET",
                    "X-Method-Override": "GET",
                    "Cache-Control": "no-cache",
                },
            )
            if method_override and _check_auth_bypass(original, method_override, url):
                findings.append(
                    _build_auth_bypass_finding(
                        url, original, method_override, "method_override_bypass"
                    )
                )
                continue

        # Test 3: Empty bearer token
        empty_bearer = response_cache.request(
            url, headers={"Authorization": "Bearer ", "Cache-Control": "no-cache"}
        )
        if empty_bearer and _check_auth_bypass(original, empty_bearer, url):
            findings.append(
                _build_auth_bypass_finding(url, original, empty_bearer, "empty_bearer_token")
            )
            continue

        # Test 4: Null/undefined token
        null_token = response_cache.request(
            url, headers={"Authorization": "null", "Cache-Control": "no-cache"}
        )
        if null_token and _check_auth_bypass(original, null_token, url):
            findings.append(_build_auth_bypass_finding(url, original, null_token, "null_token"))
            continue

    return findings


def _check_auth_bypass(original: dict[str, Any], unauth: dict[str, Any], url: str) -> bool:
    """Check if unauth response indicates auth bypass."""
    status_code_raw: Any = unauth.get("status_code")
    if not status_code_raw or int(status_code_raw) >= 400:
        return False

    similarity = round(
        SequenceMatcher(
            None,
            normalize_compare_text(original.get("body_text") or ""),
            normalize_compare_text(unauth.get("body_text") or ""),
        ).ratio(),
        3,
    )

    original_key_fields = sorted(extract_key_fields(original.get("body_text") or ""))
    unauth_key_fields = sorted(extract_key_fields(unauth.get("body_text") or ""))
    shared_key_fields = set(original_key_fields) & set(unauth_key_fields)

    baseline_has_auth_signals = _response_has_auth_signals(original)

    if not baseline_has_auth_signals and not shared_key_fields:
        return False

    parsed = _parse_json_payload(unauth)
    if parsed is None and not shared_key_fields:
        return False

    if similarity < 0.55 and not shared_key_fields:
        return False

    return True


def _build_auth_bypass_finding(
    url: str, original: dict[str, Any], unauth: dict[str, Any], bypass_type: str
) -> dict[str, Any]:
    """Build an auth bypass finding dict."""
    similarity = round(
        SequenceMatcher(
            None,
            normalize_compare_text(original.get("body_text") or ""),
            normalize_compare_text(unauth.get("body_text") or ""),
        ).ratio(),
        3,
    )

    original_key_fields = sorted(extract_key_fields(original.get("body_text") or ""))
    unauth_key_fields = sorted(extract_key_fields(unauth.get("body_text") or ""))
    shared_key_fields = sorted(set(original_key_fields) & set(unauth_key_fields))

    evidence_level = (
        "strong"
        if original.get("status_code") == unauth.get("status_code") and similarity >= 0.9
        else "moderate"
    )

    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        "original_status": original.get("status_code"),
        "unauth_status": unauth.get("status_code"),
        "same_status": original.get("status_code") == unauth.get("status_code"),
        "body_similarity": similarity,
        "shared_key_fields": shared_key_fields[:12],
        "key_fields": unauth_key_fields[:12],
        "json_accessible": _parse_json_payload(unauth) is not None,
        "baseline_has_auth_signals": _response_has_auth_signals(original),
        "evidence_level": evidence_level,
        "bypass_type": bypass_type,
    }
