"""HTTP method probes for security testing.

Contains probes for OPTIONS, Origin reflection, HEAD, CORS preflight,
and TRACE methods. Extracted from active_probes.py for better separation of concerns.
"""

from typing import Any, cast
from urllib.parse import urlparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, ensure_endpoint_key
from src.analysis.passive.runtime import ResponseCache

# Type alias for response headers
HeadersDict = dict[str, str]

# Confidence scores for HTTP method probe issue types (Fix Audit #12)
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
    "preflight_allows_delete": 0.68,
    "preflight_allows_patch": 0.68,
    "preflight_allows_authorization_header": 0.82,
    "trace_method_accepted": 0.70,
    "trace_reflects_headers": 0.78,
    "wildcard_origin_with_credentials": 0.95,
    "reflected_origin_with_credentials": 0.90,
    "null_origin_accepted": 0.75,
    "null_origin_with_credentials": 0.85,
    "missing_vary_origin": 0.60,
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
    "preflight_allows_delete": "high",
    "preflight_allows_patch": "medium",
    "preflight_allows_authorization_header": "high",
    "trace_method_accepted": "medium",
    "trace_reflects_headers": "high",
    "wildcard_origin_with_credentials": "critical",
    "reflected_origin_with_credentials": "high",
    "null_origin_accepted": "medium",
    "null_origin_with_credentials": "high",
    "missing_vary_origin": "low",
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
    """Probe for Origin header reflection weaknesses. (Fix Audit #19)"""
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

        domain = urlparse(url).netloc.split(":")[0]
        # Sanitize domain to prevent injection into Origin header
        import re as _re
        domain = _re.sub(r"[^a-zA-Z0-9.\-]", "", domain)
        # Multiple probe origins (Fix Audit #19)
        probe_origins = [
            "https://probe.invalid",
            "null",
            f"https://evil.{domain}" if domain else "https://evil.local",
            f"https://{domain}.evil.com" if domain else "https://target.evil.com",
        ]

        for probe_origin in probe_origins:
            response = response_cache.request(url, method="GET", headers={"Origin": probe_origin})
            if not response:
                continue

            headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
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
            break  # One hit per URL is enough for reflection

        if len(findings) >= limit:
            break
    return findings


def head_method_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 8
) -> list[dict[str, Any]]:
    """Compare GET and HEAD responses for inconsistencies. (Fix Audit #34)"""
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

        get_resp = response_cache.get(url)
        head_resp = response_cache.request(url, method="HEAD")
        if not get_resp or not head_resp:
            continue

        issues: list[str] = []
        if get_resp.get("status_code") != head_resp.get("status_code"):
            issues.append("head_status_mismatch")

        get_headers = {str(k).lower(): str(v) for k, v in (get_resp.get("headers") or {}).items()}
        head_headers = {str(k).lower(): str(v) for k, v in (head_resp.get("headers") or {}).items()}

        # Check Content-Length (Fix Audit #34)
        gl = get_headers.get("content-length")
        hl = head_headers.get("content-length")
        if gl and hl and gl != hl:
            issues.append("content_length_mismatch")

        # Check if security headers are missing only on HEAD (Fix Audit #34)
        sec_headers = {"x-frame-options", "content-security-policy", "x-content-type-options"}
        missing_on_head = [h for h in sec_headers if h in get_headers and h not in head_headers]
        if missing_on_head:
            issues.append("head_missing_headers")

        if issues:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": issues,
                    "confidence": _probe_confidence(issues),
                    "severity": _probe_severity(issues),
                }
            )
        if len(findings) >= limit:
            break
    return findings


def cors_preflight_probe(
    priority_urls: list[dict[str, Any]], response_cache: ResponseCache, limit: int = 8
) -> list[dict[str, Any]]:
    """Probe for CORS misconfigurations via OPTIONS preflight. (Fix Audit #35)"""
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

        headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
        acao = headers.get("access-control-allow-origin", "").strip()
        acac = headers.get("access-control-allow-credentials", "").lower()
        acam = headers.get("access-control-allow-methods", "").upper()
        acah = headers.get("access-control-allow-headers", "").lower()
        vary = headers.get("vary", "").lower()

        issues: list[str] = []

        if acao == "*" and acac == "true":
            issues.append("wildcard_origin_with_credentials")
        elif acao == probe_origin and acac == "true":
            issues.append("reflected_origin_with_credentials")

        # Test 2: Null origin - always run independently (Fix Audit #35)
        null_resp = response_cache.request(url, method="OPTIONS", headers={"Origin": "null"})
        if null_resp:
            nh = {str(k).lower(): str(v) for k, v in (null_resp.get("headers") or {}).items()}
            if nh.get("access-control-allow-origin") == "null":
                issues.append("null_origin_accepted")
                if nh.get("access-control-allow-credentials") == "true":
                    issues.append("null_origin_with_credentials")

        if "PUT" in acam:
            issues.append("preflight_allows_put")
        if "DELETE" in acam:
            issues.append("preflight_allows_delete")
        if "PATCH" in acam:
            issues.append("preflight_allows_patch")
        if "authorization" in acah or "*" in acah:
            issues.append("preflight_allows_authorization_header")
        if acao and "origin" not in vary:
            issues.append("missing_vary_origin")

        if issues:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": issues,
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
    """Probe for TRACE exposure. (Fix Audit #33)"""
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
        # Fix Audit #33: Include 301/302 as some servers redirect TRACE
        if status in {200, 202, 204, 301, 302}:
            issues: list[str] = ["trace_method_accepted"]
            body = str(response.get("body_text", "")).lower()
            if any(token in body for token in ("cookie", "authorization", "x-api-key")):
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
