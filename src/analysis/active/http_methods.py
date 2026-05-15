"""HTTP method probes for security testing.

Contains probes for OPTIONS, Origin reflection, HEAD, CORS preflight,
and TRACE methods. Extracted from active_probes.py for better separation of concerns.
"""

from typing import Any, cast

from src.analysis.helpers import classify_endpoint, endpoint_base_key, ensure_endpoint_key
from src.analysis.passive.runtime import ResponseCache

# Type alias for response headers
HeadersDict = dict[str, str]

# Confidence scores for HTTP method probe issue types
PROBE_CONFIDENCE = {
    "unsafe_methods_exposed": 0.72,
    "trace_enabled": 0.68,
    "origin_reflection": 0.82,
    "credentialed_cors": 0.88,
    "permissive_cors": 0.65,
    "head_status_mismatch": 0.58,
    "head_missing_headers": 0.45,
    "content_length_mismatch": 0.52,
    "preflight_origin_allowed": 0.75,
    "preflight_allows_put": 0.68,
    "preflight_allows_authorization_header": 0.82,
    "trace_method_accepted": 0.70,
    "trace_reflects_headers": 0.78,
}

PROBE_SEVERITY = {
    "unsafe_methods_exposed": "medium",
    "trace_enabled": "low",
    "origin_reflection": "high",
    "credentialed_cors": "high",
    "permissive_cors": "medium",
    "head_status_mismatch": "low",
    "head_missing_headers": "info",
    "content_length_mismatch": "low",
    "preflight_origin_allowed": "medium",
    "preflight_allows_put": "medium",
    "preflight_allows_authorization_header": "high",
    "trace_method_accepted": "medium",
    "trace_reflects_headers": "high",
}


def _probe_confidence(issues: list[str]) -> float:
    if not issues:
        return 0.5
    max_conf = max(PROBE_CONFIDENCE.get(issue, 0.5) for issue in issues)
    bonus = min(0.06, len(issues) * 0.02)
    return round(min(max_conf + bonus, 0.98), 2)


def _probe_severity(issues: list[str]) -> str:
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    if not issues:
        return "low"
    return PROBE_SEVERITY.get(
        max(issues, key=lambda i: severity_order.get(PROBE_SEVERITY.get(i, "low"), 0)), "low"
    )


def options_method_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 10
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in priority_urls:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        endpoint_key = ensure_endpoint_key(item, url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)
        response = response_cache.request(url, method="OPTIONS")
        if not response:
            continue
        raw_headers: Any = response.get("headers") or {}
        headers: HeadersDict = {
            str(key).lower(): str(value) for key, value in cast(dict[str, Any], raw_headers).items()
        }
        allow_values = sorted(
            {part.strip().upper() for part in headers.get("allow", "").split(",") if part.strip()}
        )
        issues: list[str] = []
        if any(method in {"PUT", "DELETE", "PATCH"} for method in allow_values):
            issues.append("unsafe_methods_exposed")
        if "TRACE" in allow_values:
            issues.append("trace_enabled")
        if issues:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "status_code": response.get("status_code"),
                    "allowed_methods": allow_values,
                    "issues": issues,
                    "confidence": _probe_confidence(issues),
                    "severity": _probe_severity(issues),
                }
            )
        if len(findings) >= limit:
            break
    return findings


def origin_reflection_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 8
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    probe_origin = "https://probe.invalid"
    for item in priority_urls:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        endpoint_key = ensure_endpoint_key(item, url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)
        response = response_cache.request(url, method="GET", headers={"Origin": probe_origin})
        if not response:
            continue
        raw_headers: Any = response.get("headers") or {}
        headers: HeadersDict = {
            str(key).lower(): str(value) for key, value in cast(dict[str, Any], raw_headers).items()
        }
        acao = headers.get("access-control-allow-origin", "").strip()
        acac = headers.get("access-control-allow-credentials", "").strip().lower()
        if acao not in {probe_origin, "*"}:
            continue
        issues: list[str] = []
        if acao == probe_origin:
            issues.append("origin_reflection")
        if acac == "true":
            issues.append("credentialed_cors")
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "status_code": response.get("status_code"),
                "probe_origin": probe_origin,
                "allow_origin": acao,
                "allow_credentials": acac == "true",
                "confidence": _probe_confidence(issues or ["permissive_cors"]),
                "severity": _probe_severity(issues or ["permissive_cors"]),
                "issues": issues or ["permissive_cors"],
            }
        )
        if len(findings) >= limit:
            break
    return findings


def head_method_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 8
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in priority_urls:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        endpoint_key = ensure_endpoint_key(item, url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)
        get_response = response_cache.get(url)
        head_response = response_cache.request(url, method="HEAD")
        if not get_response or not head_response:
            continue
        issues: list[str] = []
        if get_response.get("status_code") != head_response.get("status_code"):
            issues.append("head_status_mismatch")
        if not head_response.get("headers"):
            issues.append("head_missing_headers")
        get_raw_headers: Any = get_response.get("headers") or {}
        get_headers: HeadersDict = {
            str(k).lower(): str(v) for k, v in cast(dict[str, Any], get_raw_headers).items()
        }
        head_raw_headers: Any = head_response.get("headers") or {}
        head_headers: HeadersDict = {
            str(k).lower(): str(v) for k, v in cast(dict[str, Any], head_raw_headers).items()
        }
        get_length = str(get_headers.get("content-length", ""))
        head_length = str(head_headers.get("content-length", ""))
        # Note: head_headers is also available for additional header comparison checks
        if get_length and head_length and get_length != head_length:
            issues.append("content_length_mismatch")
        if issues:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "confidence": _probe_confidence(issues),
                    "severity": _probe_severity(issues),
                    "get_status": get_response.get("status_code"),
                    "head_status": head_response.get("status_code"),
                    "issues": issues,
                }
            )
        if len(findings) >= limit:
            break
    return findings


def cors_preflight_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 8
) -> list[dict[str, Any]]:
    """Probe for CORS misconfigurations via OPTIONS preflight requests.

    Tests for:
    - Wildcard origin with credentials (critical)
    - Null origin acceptance (medium)
    - Reflected origin with credentials (high)
    - Overly permissive methods (PUT, DELETE, PATCH)
    - Authorization header allowance
    - Missing Vary: Origin header (cache poisoning risk)
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    probe_origin = "https://probe.invalid"
    null_origin = "null"

    for item in priority_urls:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        endpoint_key = ensure_endpoint_key(item, url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        # Test 1: Standard preflight with probe origin
        response = response_cache.request(
            url,
            method="OPTIONS",
            headers={
                "Origin": probe_origin,
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        if not response:
            continue

        raw_headers: Any = response.get("headers") or {}
        headers: HeadersDict = {
            str(key).lower(): str(value) for key, value in cast(dict[str, Any], raw_headers).items()
        }
        acao = headers.get("access-control-allow-origin", "").strip()
        acam = headers.get("access-control-allow-methods", "").upper()
        acah = headers.get("access-control-allow-headers", "").lower()
        acac = headers.get("access-control-allow-credentials", "").lower()
        vary = headers.get("vary", "").lower()

        issues: list[str] = []
        cors_details: list[dict[str, str]] = []

        # Check for wildcard origin with credentials (critical)
        if acao == "*" and acac == "true":
            issues.append("wildcard_origin_with_credentials")
            cors_details.append({"type": "wildcard_with_creds", "severity": "critical"})
        # Check for reflected origin with credentials (high)
        elif acao == probe_origin and acac == "true":
            issues.append("reflected_origin_with_credentials")
            cors_details.append({"type": "reflected_origin_with_creds", "severity": "high"})
        # Check for null origin acceptance (medium)

        # Test 2: Null origin preflight
        null_response = response_cache.request(
            url,
            method="OPTIONS",
            headers={
                "Origin": null_origin,
                "Access-Control-Request-Method": "GET",
            },
        )
        if null_response:
            null_raw_headers: Any = null_response.get("headers") or {}
            null_headers: HeadersDict = {
                str(k).lower(): str(v) for k, v in cast(dict[str, Any], null_raw_headers).items()
            }
            null_acao = null_headers.get("access-control-allow-origin", "").strip()
            null_acac = null_headers.get("access-control-allow-credentials", "").lower()
            if null_acao == null_origin:
                issues.append("null_origin_accepted")
                cors_details.append({"type": "null_origin", "severity": "medium"})
                if null_acac == "true":
                    issues.append("null_origin_with_credentials")
                    cors_details.append({"type": "null_origin_with_creds", "severity": "high"})

        # Check for overly permissive methods
        if "PUT" in acam or "*" in acam:
            issues.append("preflight_allows_put")
        if "DELETE" in acam:
            issues.append("preflight_allows_delete")
        if "PATCH" in acam:
            issues.append("preflight_allows_patch")

        # Check for authorization header allowance
        if "authorization" in acah or "*" in acah:
            issues.append("preflight_allows_authorization_header")

        # Check for missing Vary: Origin header (cache poisoning risk)
        if acao and "origin" not in vary:
            issues.append("missing_vary_origin")

        if issues:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "status_code": response.get("status_code"),
                    "issues": issues,
                    "cors_details": cors_details,
                    "confidence": _probe_confidence(issues),
                    "severity": _probe_severity(issues),
                }
            )
        if len(findings) >= limit:
            break
    return findings


def trace_method_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 5
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in priority_urls:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        endpoint_key = ensure_endpoint_key(item, url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)
        response = response_cache.request(url, method="TRACE")
        if not response:
            continue
        status = int(response.get("status_code") or 0)
        if status in {200, 202, 204}:
            issues: list[str] = ["trace_method_accepted"]
            body = str(response.get("body_text", "")).lower()
            if any(
                token in body for token in ("cookie", "authorization", "x-forwarded", "x-api-key")
            ):
                issues.append("trace_reflects_headers")
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "status_code": status,
                    "issues": issues,
                    "confidence": _probe_confidence(issues),
                    "severity": _probe_severity(issues),
                }
            )
        if len(findings) >= limit:
            break
    return findings
