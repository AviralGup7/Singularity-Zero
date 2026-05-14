"""Token Lifetime & Rotation Analyzer (Passive).

Examines authentication tokens across responses for lifetime and rotation
issues including JWT expiration analysis, session cookie configuration,
API key patterns, and token reuse detection.

This package modularizes the token lifetime analyzer into separate files
for better maintainability and AI-agent editability.
"""

from re import Match
from typing import Any, cast
from urllib.parse import parse_qsl, urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
    token_shape,
)
from src.analysis.passive.patterns import JWT_RE

from ._analyzers import analyze_jwt_token, parse_set_cookie
from ._constants import (
    API_KEY_RE,
    JWT_LIKE_RE,
    THIRTY_DAYS_SECONDS,
    TOKEN_IN_URL_RE,
    TOKEN_LIFETIME_ANALYZER_SPEC,
)
from ._helpers import compute_confidence, determine_severity, severity_score

__all__ = ["token_lifetime_analyzer", "TOKEN_LIFETIME_ANALYZER_SPEC"]


def token_lifetime_analyzer(
    urls: set[str],
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Analyze authentication tokens for lifetime and rotation issues."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    token_registry: dict[str, list[dict[str, Any]]] = {}
    api_key_registry: dict[str, list[dict[str, Any]]] = {}

    # Scan URLs for token parameters
    for raw_url in sorted(urls):
        if is_noise_url(raw_url):
            continue
        parsed = urlparse(raw_url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

        for param_name, param_value in query_pairs:
            if TOKEN_IN_URL_RE.match(f"{param_name}={param_value}"):
                endpoint_key = endpoint_signature(raw_url)
                dedup_key = f"token_url:{endpoint_key}:{param_name}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    {
                        "url": raw_url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": endpoint_base_key(raw_url),
                        "endpoint_type": classify_endpoint(raw_url),
                        "category": "token_lifetime_rotation",
                        "title": f"Token '{param_name}' exposed in URL parameter",
                        "severity": "high",
                        "confidence": 0.90,
                        "score": severity_score("high"),
                        "signals": ["token_in_url_parameter"],
                        "evidence": {
                            "parameter": param_name,
                            "value_preview": (param_value[:20] + "...")
                            if len(param_value) > 20
                            else param_value,
                            "token_shape": token_shape(param_value),
                        },
                        "explanation": (
                            f"The parameter '{param_name}' contains a token-like value in the URL query string. "
                            f"Tokens in URLs can be leaked through browser history, server logs, referer headers, "
                            f"and bookmark sharing. Tokens should only be transmitted via headers or secure cookies."
                        ),
                    }
                )

            if JWT_LIKE_RE.search(param_value):
                endpoint_key = endpoint_signature(raw_url)
                dedup_key = f"jwt_url:{endpoint_key}:{param_name}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                result = analyze_jwt_token(param_value, raw_url)
                if result:
                    result["category"] = "token_lifetime_rotation"
                    result["title"] = f"JWT token in URL parameter '{param_name}'"
                    result["location"] = "url_parameter"
                    result["parameter"] = param_name
                    findings.append(result)

    # Scan responses for tokens
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue

        body = str(response.get("body_text") or "")
        raw_headers: Any = response.get("headers") or {}
        headers: dict[str, str] = {
            str(k).lower(): str(v) for k, v in cast(dict[str, Any], raw_headers).items()
        }
        status_code = response.get("status_code")

        # JWT tokens in body
        jwt_matches = JWT_RE.findall(body) if body else []
        jwt_matches.extend(JWT_LIKE_RE.findall(body) if body else [])
        for token in jwt_matches[:10]:
            endpoint_key = endpoint_signature(url)
            dedup_key = f"jwt_body:{endpoint_key}:{token[:30]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            result = analyze_jwt_token(token, url)
            if result:
                result["category"] = "token_lifetime_rotation"
                result["title"] = f"JWT token found in response body from {endpoint_key}"
                result["location"] = "response_body"
                findings.append(result)
            token_registry.setdefault(token[:50], []).append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "location": "response_body",
                }
            )

        # JWT in Authorization header
        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            bearer_token = auth_header[7:].strip()
            if JWT_LIKE_RE.search(bearer_token):
                endpoint_key = endpoint_signature(url)
                dedup_key = f"jwt_auth:{endpoint_key}:{bearer_token[:30]}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    result = analyze_jwt_token(bearer_token, url)
                    if result:
                        result["category"] = "token_lifetime_rotation"
                        result["title"] = "JWT token in Authorization header"
                        result["location"] = "authorization_header"
                        findings.append(result)

        # Set-Cookie analysis
        set_cookie_headers = []
        raw_set_cookie = headers.get("set-cookie", "")
        if raw_set_cookie:
            if isinstance(raw_set_cookie, list):
                set_cookie_headers = [str(c) for c in raw_set_cookie]
            else:
                set_cookie_headers = [c.strip() for c in raw_set_cookie.split("\n") if c.strip()]

        for cookie_string in set_cookie_headers:
            cookie_info = parse_set_cookie(cookie_string)
            cookie_name = cookie_info["name"]
            if not cookie_name:
                continue

            is_session_cookie = cookie_info["max_age"] is None and cookie_info["expires"] is None
            is_long_lived = (
                cookie_info["max_age"] is not None and cookie_info["max_age"] > THIRTY_DAYS_SECONDS
            )

            issues: list[str] = []
            signals: list[str] = []
            if is_session_cookie:
                signals.append("session_cookie_no_expiration")
                issues.append("cookie_no_expiration")
            if is_long_lived:
                signals.append(f"long_max_age:{cookie_info['max_age']}s")
                issues.append("cookie_long_max_age")

            if cookie_info["value"] and JWT_LIKE_RE.search(cookie_info["value"]):
                result = analyze_jwt_token(cookie_info["value"], url)
                if result:
                    result["category"] = "token_lifetime_rotation"
                    result["title"] = f"JWT token in Set-Cookie '{cookie_name}'"
                    result["location"] = "cookie"
                    result["cookie_name"] = cookie_name
                    findings.append(result)

            token_registry.setdefault(cookie_info["value"][:50], []).append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "location": f"cookie:{cookie_name}",
                }
            )

            if issues:
                severity = determine_severity(issues)
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_signature(url),
                        "endpoint_base_key": endpoint_base_key(url),
                        "endpoint_type": classify_endpoint(url),
                        "status_code": status_code,
                        "category": "token_lifetime_rotation",
                        "title": f"Session cookie '{cookie_name}' lifetime issue",
                        "severity": severity,
                        "confidence": compute_confidence(issues),
                        "score": severity_score(severity),
                        "signals": sorted(signals),
                        "evidence": {
                            "cookie_name": cookie_name,
                            "max_age": cookie_info["max_age"],
                            "expires": cookie_info["expires"],
                            "secure": cookie_info["secure"],
                            "httponly": cookie_info["httponly"],
                            "samesite": cookie_info["samesite"],
                        },
                        "explanation": (
                            "The cookie '{}' has {}. ".format(
                                cookie_name,
                                "no expiration set (session cookie)"
                                if is_session_cookie
                                else "a long max-age of {} seconds".format(cookie_info["max_age"]),
                            )
                            + "Session cookies without explicit expiration may persist indefinitely. "
                            + "Long-lived cookies increase the window for token theft and replay attacks."
                        ),
                    }
                )

        # API key detection
        api_key_matches: list[Match[str]] | Any = list(API_KEY_RE.finditer(body)) if body else []
        for match in api_key_matches:
            key_value: str = str(match.group(1))
            endpoint_key = endpoint_signature(url)
            dedup_key = f"apikey:{endpoint_key}:{key_value[:20]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            api_key_registry.setdefault(key_value[:30], []).append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                }
            )

        # API key in frontend code
        if body and any(
            token in body.lower()
            for token in ("api_key", "apikey", "api-token", "api_secret", "api-secret")
        ):
            if any(
                hint in url.lower()
                for hint in (
                    ".js",
                    ".jsx",
                    ".ts",
                    ".tsx",
                    "/static/",
                    "/assets/",
                    "/js/",
                    "/scripts/",
                )
            ):
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_signature(url),
                        "endpoint_base_key": endpoint_base_key(url),
                        "endpoint_type": classify_endpoint(url),
                        "status_code": status_code,
                        "category": "token_lifetime_rotation",
                        "title": "API key references detected in frontend code",
                        "severity": "high",
                        "confidence": 0.85,
                        "score": severity_score("high"),
                        "signals": ["api_key_in_frontend"],
                        "evidence": {
                            "resource_type": "frontend_javascript",
                            "url_path": urlparse(url).path,
                        },
                        "explanation": (
                            "API key references were detected in a JavaScript/frontend resource. "
                            "API keys embedded in client-side code are publicly accessible and should "
                            "never be used for server-side authentication. Consider using short-lived "
                            "tokens or backend proxying instead."
                        ),
                    }
                )

    # Token reuse detection
    for token_prefix, occurrences in token_registry.items():
        if len(occurrences) >= 3:
            unique_endpoints = {o["endpoint_key"] for o in occurrences}
            if len(unique_endpoints) >= 2:
                dedup_key = f"token_reuse:{token_prefix}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(
                        {
                            "url": occurrences[0]["url"],
                            "endpoint_key": occurrences[0]["endpoint_key"],
                            "endpoint_base_key": endpoint_base_key(occurrences[0]["url"]),
                            "endpoint_type": classify_endpoint(occurrences[0]["url"]),
                            "category": "token_lifetime_rotation",
                            "title": f"Token reused across {len(unique_endpoints)} endpoints",
                            "severity": "high",
                            "confidence": 0.80,
                            "score": severity_score("high"),
                            "signals": ["token_not_rotated"],
                            "evidence": {
                                "token_prefix": token_prefix + "...",
                                "occurrence_count": len(occurrences),
                                "unique_endpoints": len(unique_endpoints),
                                "locations": sorted({o["location"] for o in occurrences}),
                            },
                            "explanation": (
                                f"The same token value was observed across {len(unique_endpoints)} different endpoints "
                                f"({len(occurrences)} total occurrences). Tokens that are not rotated between requests "
                                f"or endpoints increase the risk of replay attacks. Consider implementing token rotation "
                                f"with short-lived tokens."
                            ),
                        }
                    )

    # API key reuse detection
    for key_prefix, occurrences in api_key_registry.items():
        if len(occurrences) >= 2:
            unique_endpoints = {o["endpoint_key"] for o in occurrences}
            if len(unique_endpoints) >= 2:
                dedup_key = f"apikey_reuse:{key_prefix}"
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(
                        {
                            "url": occurrences[0]["url"],
                            "endpoint_key": occurrences[0]["endpoint_key"],
                            "endpoint_base_key": endpoint_base_key(occurrences[0]["url"]),
                            "endpoint_type": classify_endpoint(occurrences[0]["url"]),
                            "category": "token_lifetime_rotation",
                            "title": f"API key reused across {len(unique_endpoints)} endpoints",
                            "severity": "medium",
                            "confidence": 0.75,
                            "score": severity_score("medium"),
                            "signals": ["api_key_reused"],
                            "evidence": {
                                "key_prefix": key_prefix + "...",
                                "occurrence_count": len(occurrences),
                                "unique_endpoints": len(unique_endpoints),
                            },
                            "explanation": (
                                f"The same API key pattern was observed across {len(unique_endpoints)} different endpoints. "
                                f"Static API keys that do not rotate increase the impact of key compromise. "
                                f"Consider using short-lived tokens or per-request signatures."
                            ),
                        }
                    )

    findings.sort(
        key=lambda item: (-item.get("score", 0), -item.get("confidence", 0), item.get("url", ""))
    )
    return findings[:150]
