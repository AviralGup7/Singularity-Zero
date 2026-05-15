"""WebSocket hijacking active probe."""

import re
from typing import Any
from urllib.parse import urlparse

from src.analysis._core.http_request import _safe_request
from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache

from ._confidence import probe_confidence, probe_severity

WS_PATH_HINTS = {
    "/ws",
    "/websocket",
    "/socket",
    "/socket.io",
    "/wss",
    "/realtime",
    "/live",
    "/stream",
    "/channel",
    "/subscribe",
    "/push",
    "/notification",
    "/chat",
    "/messaging",
    "/signal",
    "/graphql/subscriptions",
    "/ws/",
    "/socket/",
}

WS_PARAM_NAMES = {
    "ws",
    "websocket",
    "socket",
    "channel",
    "room",
    "subscribe",
    "topic",
    "stream",
}

ORIGIN_VALUES = [
    ("null_origin", "null"),
    ("evil_origin", "https://evil.com"),
    ("attacker_origin", "https://attacker.com"),
    ("localhost_origin", "http://localhost:8080"),
    ("empty_origin", ""),
]

WS_ERROR_RE = re.compile(
    r"(?i)(?:websocket|WebSocket|WS_ERROR|connection.*refused|"
    r"upgrade.*required|invalid.*upgrade|expected.*101|"
    r"WebSocket.*error|ws.*error|socket.*error)"
)

WS_AUTH_ERROR_RE = re.compile(
    r"(?i)(?:unauthorized|authentication.*required|not.*authenticated|"
    r"invalid.*token|missing.*token|access.*denied|forbidden|"
    r"auth.*required|login.*required)"
)


def _is_ws_endpoint(url: str, response: dict[str, Any] | None = None) -> bool:
    lowered = url.lower()
    if any(hint in lowered for hint in WS_PATH_HINTS):
        return True
    if response:
        headers = {str(k).lower(): str(v) for k, v in response.get("headers", {}).items()}
        upgrade = headers.get("upgrade", "")
        if "websocket" in upgrade.lower():
            return True
        body = str(response.get("body_text") or response.get("body") or "").lower()
        if "websocket" in body or "socket.io" in body or "ws://" in body or "wss://" in body:
            return True
    return False


def _get_ws_http_url(url: str) -> str:
    if url.startswith("wss://"):
        return "https://" + url[6:]
    elif url.startswith("ws://"):
        return "http://" + url[5:]
    return url


def websocket_hijacking_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test endpoints for WebSocket security vulnerabilities.

    Tests cross-site WebSocket hijacking via origin validation,
    authentication token requirements, missing origin header handling,
    arbitrary origin acceptance, and WebSocket endpoint enumeration.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of WebSocket hijacking findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url or not url.startswith(("http://", "https://", "ws://", "wss://")):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        http_url = _get_ws_http_url(url)
        original_resp = response_cache.get(http_url)
        if not original_resp:
            original_resp = _safe_request(http_url, timeout=8)
        if not original_resp or original_resp.get("status") in (404, 410, 503):
            if not _is_ws_endpoint(url, original_resp):
                continue

        original_resp.get("status", 0)
        original_headers = original_resp.get("headers", {})

        if not _is_ws_endpoint(url, original_resp):
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        auth_header = None
        for key, val in original_headers.items():
            if key.lower() in ("authorization", "x-auth-token", "x-access-token"):
                auth_header = key
                break

        for origin_name, origin_value in ORIGIN_VALUES:
            test_headers = {
                "Origin": origin_value,
                "Host": urlparse(http_url).netloc,
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            }
            if auth_header:
                test_headers[auth_header] = original_headers.get(auth_header, "")

            response = _safe_request(http_url, headers=test_headers, timeout=10)
            if not response:
                continue

            status = response.get("status", 0)
            resp_headers = {str(k).lower(): str(v) for k, v in response.get("headers", {}).items()}

            issues_for_hit: list[str] = []

            if status == 101:
                if origin_value in ("https://evil.com", "https://attacker.com", "null"):
                    issues_for_hit.append("ws_cross_origin_accepted")
                elif origin_value == "":
                    issues_for_hit.append("ws_empty_origin_accepted")
            elif status == 200:
                body = str(response.get("body") or "")
                if "websocket" in body.lower() or "connected" in body.lower():
                    if origin_value in ("https://evil.com", "https://attacker.com"):
                        issues_for_hit.append("ws_cross_origin_200_response")

            if resp_headers.get("access-control-allow-origin") == "*":
                if "ws_cors_wildcard" not in url_issues:
                    issues_for_hit.append("ws_cors_wildcard")

            if issues_for_hit:
                url_issues.extend(issues_for_hit)
                url_probes.append(
                    {
                        "test": "origin_validation",
                        "origin_name": origin_name,
                        "origin_value": origin_value,
                        "status_code": status,
                        "issues": issues_for_hit,
                    }
                )

        no_origin_headers = {
            "Host": urlparse(http_url).netloc,
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        }
        response = _safe_request(http_url, headers=no_origin_headers, timeout=10)
        if response:
            status = response.get("status", 0)
            if status == 101:
                url_issues.append("ws_missing_origin_accepted")
                url_probes.append(
                    {
                        "test": "missing_origin",
                        "status_code": status,
                        "issues": ["ws_missing_origin_accepted"],
                    }
                )

        no_auth_headers = {
            "Origin": urlparse(http_url).scheme + "://" + urlparse(http_url).netloc,
            "Host": urlparse(http_url).netloc,
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        }
        response = _safe_request(http_url, headers=no_auth_headers, timeout=10)
        if response:
            status = response.get("status", 0)
            body = str(response.get("body") or "")
            if status == 101:
                url_issues.append("ws_no_auth_accepted")
                url_probes.append(
                    {
                        "test": "no_authentication",
                        "status_code": status,
                        "issues": ["ws_no_auth_accepted"],
                    }
                )
            elif status == 200 and not WS_AUTH_ERROR_RE.search(body):
                url_issues.append("ws_no_auth_200_response")
                url_probes.append(
                    {
                        "test": "no_authentication",
                        "status_code": status,
                        "issues": ["ws_no_auth_200_response"],
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
