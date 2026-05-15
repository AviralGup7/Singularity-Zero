"""Clickjacking Active Test - Active probe for clickjacking vulnerabilities.

Tests endpoints for missing or weak anti-clickjacking protections including
X-Frame-Options, Content-Security-Policy frame-ancestors, and frame-busting
JavaScript. Actively probes endpoints that lack protections.
"""

import re
from typing import Any

import requests

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    normalize_headers,
)
from src.analysis.helpers.scoring import severity_score
from src.analysis.plugins import AnalysisPluginSpec
from src.core.utils.url_validation import is_safe_url

CLICKJACKING_TEST_SPEC = AnalysisPluginSpec(
    key="clickjacking_test",
    label="Clickjacking Active Test",
    description="Actively test endpoints for clickjacking vulnerabilities by checking missing framing protections and testing actual framing behavior.",
    group="active",
    slug="clickjacking_test",
    enabled_by_default=True,
)

_FRAME_BUST_PATTERNS = [
    re.compile(r"if\s*\(\s*top\s*!==?\s*self\s*\)", re.IGNORECASE),
    re.compile(r"if\s*\(\s*window\s*!==?\s*top\s*\)", re.IGNORECASE),
    re.compile(r"if\s*\(\s*self\s*!==?\s*top\s*\)", re.IGNORECASE),
    re.compile(r"if\s*\(\s*top\s*==\s*self\s*\)", re.IGNORECASE),
    re.compile(r"break-frames", re.IGNORECASE),
    re.compile(r"framebuster", re.IGNORECASE),
    re.compile(r"frame.?bust", re.IGNORECASE),
    re.compile(r"frame.?killer", re.IGNORECASE),
    re.compile(r"prevent.?frame", re.IGNORECASE),
    re.compile(r"top\.location\s*=", re.IGNORECASE),
    re.compile(r"self\.location\s*=\s*top\.location", re.IGNORECASE),
    re.compile(r"window\.top\.location", re.IGNORECASE),
    re.compile(r"parent\.location\s*=", re.IGNORECASE),
]

_SENSITIVE_ENDPOINT_PATTERNS = [
    "/auth",
    "/login",
    "/signin",
    "/signup",
    "/register",
    "/oauth",
    "/token",
    "/session",
    "/password",
    "/reset",
    "/forgot",
    "/payment",
    "/checkout",
    "/billing",
    "/card",
    "/purchase",
    "/admin",
    "/dashboard",
    "/settings",
    "/profile",
    "/account",
    "/user",
    "/users/me",
    "/api/key",
    "/api/token",
    "/transfer",
    "/withdraw",
    "/deposit",
    "/bank",
    "/delete",
    "/remove",
    "/disable",
    "/enable",
    "/permission",
    "/role",
    "/grant",
    "/revoke",
]

_CDN_WAF_FRAME_HEADERS = {
    "cf-ray",
    "x-cdn",
    "x-sucuri-id",
    "x-akamai-transformed",
    "x-amz-cf-id",
    "x-fastly-request-id",
}


def _safe_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    req_headers = dict(headers or {})
    req_headers.setdefault(
        "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityPipeline/1.0"
    )
    req_headers.setdefault("Accept", "text/html, application/xhtml+xml, */*")
    if not is_safe_url(url):
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "success": False,
            "error": "URL failed safety check",
        }
    try:
        resp = requests.request(
            method, url, headers=req_headers, data=body, timeout=timeout, verify=True
        )
        resp_body = resp.text or ""
        return {
            "status": getattr(resp, "status_code", 0),
            "headers": dict(resp.headers),
            "body": resp_body[:8000],
            "body_length": len(resp_body),
            "success": resp.status_code < 400,
        }
    except requests.RequestException as e:
        resp_body = ""
        resp_obj = getattr(e, "response", None)
        status = 0
        headers = {}
        if resp_obj is not None:
            try:
                resp_body = resp_obj.text
                status = getattr(resp_obj, "status_code", 0)
                headers = dict(resp_obj.headers)
            except Exception:
                pass
        return {
            "status": status,
            "headers": headers,
            "body": (resp_body or "")[:8000],
            "body_length": len(resp_body or ""),
            "success": False,
            "error": str(e),
        }
    except Exception as e:
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "success": False,
            "error": str(e),
        }


def _has_frame_busting_js(body: str) -> tuple[bool, list[str]]:
    """Check if response body contains frame-busting JavaScript."""
    if not body:
        return False, []
    matched: list[str] = []
    for pattern in _FRAME_BUST_PATTERNS:
        if pattern.search(body):
            matched.append(f"frame_bust_pattern:{pattern.pattern}")
    return bool(matched), matched


def _is_sensitive_endpoint(url: str) -> bool:
    """Check if URL points to a sensitive endpoint."""
    lowered = url.lower()
    return any(token in lowered for token in _SENSITIVE_ENDPOINT_PATTERNS)


def _check_x_frame_options(headers: dict[str, str]) -> dict[str, Any]:
    """Analyze X-Frame-Options header."""
    result: dict[str, Any] = {
        "present": False,
        "value": None,
        "issues": [],
    }
    xfo = headers.get("x-frame-options")
    if not xfo:
        result["issues"].append("missing_x_frame_options")
        return result
    result["present"] = True
    result["value"] = xfo
    xfo_lower = xfo.lower().strip()
    if xfo_lower == "allow-from":
        result["issues"].append("deprecated_allow_from")
    elif xfo_lower not in ("deny", "sameorigin"):
        if xfo_lower.startswith("allow-from"):
            result["issues"].append("deprecated_allow_from_with_uri")
        else:
            result["issues"].append("non_standard_xfo_value")
    return result


def _check_csp_frame_ancestors(headers: dict[str, str]) -> dict[str, Any]:
    """Analyze CSP frame-ancestors directive."""
    result: dict[str, Any] = {
        "present": False,
        "value": None,
        "directives": [],
        "issues": [],
    }
    csp = headers.get("content-security-policy") or headers.get(
        "content-security-policy-report-only"
    )
    if not csp:
        result["issues"].append("missing_csp")
        return result
    result["present"] = True
    result["value"] = csp
    csp_lower = csp.lower()
    frame_match = re.search(r"frame-ancestors\s+([^;]+)", csp_lower)
    if not frame_match:
        result["issues"].append("missing_frame_ancestors_directive")
        return result
    directive_value = frame_match.group(1).strip()
    result["directives"] = directive_value.split()
    if "*" in result["directives"]:
        result["issues"].append("overly_permissive_wildcard")
    elif "https:" in result["directives"] or "http:" in result["directives"]:
        result["issues"].append("permissive_scheme_wildcard")
    elif len(result["directives"]) == 0:
        result["issues"].append("empty_frame_ancestors")
    return result


def _check_x_permitted_cross_domain(headers: dict[str, str]) -> dict[str, Any]:
    """Check X-Permitted-Cross-Domain-Policies header."""
    result: dict[str, Any] = {
        "present": False,
        "value": None,
        "issues": [],
    }
    header_val = headers.get("x-permitted-cross-domain-policies")
    if not header_val:
        result["issues"].append("missing_x_permitted_cross_domain_policies")
        return result
    result["present"] = True
    result["value"] = header_val
    if header_val.lower() in ("all", "master-only"):
        result["issues"].append("permissive_cross_domain_policy")
    return result


def _build_finding(
    url: str,
    severity: str,
    title: str,
    category: str,
    signals: list[str],
    evidence: dict[str, Any],
    explanation: str,
    status_code: int | None = None,
) -> dict[str, Any]:
    """Build a standardized finding dict."""
    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        "status_code": status_code,
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": 0.8
        if severity in ("critical", "high")
        else 0.65
        if severity == "medium"
        else 0.5,
        "signals": signals,
        "evidence": evidence,
        "explanation": explanation,
        "score": severity_score(severity),
    }


def clickjacking_test(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Test endpoints for clickjacking vulnerabilities.

    First performs passive analysis of existing responses for missing
    anti-clickjacking headers, then actively probes unprotected endpoints
    to verify framing behavior.

    Args:
        urls: Set of URLs to test.
        responses: List of HTTP response dicts.
        limit: Maximum number of endpoints to actively probe.

    Returns:
        List of finding dicts with clickjacking vulnerability signals.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    response_by_url: dict[str, dict[str, Any]] = {}
    for resp in responses:
        resp_url = str(resp.get("url", "")).strip()
        if resp_url:
            response_by_url[resp_url] = resp

    unprotected_urls: list[tuple[str, dict[str, Any], dict[str, Any]]] = []

    for resp in responses:
        url = str(resp.get("url", "")).strip()
        if not url:
            continue
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        headers = normalize_headers(resp)
        status_code = resp.get("status_code")
        body = str(resp.get("body_text") or "")[:5000]

        xfo_result = _check_x_frame_options(headers)
        csp_result = _check_csp_frame_ancestors(headers)
        xpcd_result = _check_x_permitted_cross_domain(headers)
        has_frame_bust, bust_patterns = _has_frame_busting_js(body)

        all_issues = (
            xfo_result.get("issues", [])
            + csp_result.get("issues", [])
            + xpcd_result.get("issues", [])
        )

        if not all_issues and not has_frame_bust:
            continue

        missing_xfo = "missing_x_frame_options" in xfo_result.get("issues", [])
        missing_csp_frame = "missing_csp" in csp_result.get(
            "issues", []
        ) or "missing_frame_ancestors_directive" in csp_result.get("issues", [])
        permissive_csp = any(
            issue in csp_result.get("issues", [])
            for issue in ("overly_permissive_wildcard", "permissive_scheme_wildcard")
        )
        deprecated_xfo = "deprecated_allow_from" in xfo_result.get(
            "issues", []
        ) or "deprecated_allow_from_with_uri" in xfo_result.get("issues", [])

        is_sensitive = _is_sensitive_endpoint(url)

        signals: list[str] = []
        evidence: dict[str, Any] = {
            "x_frame_options": xfo_result,
            "csp_frame_ancestors": csp_result,
            "x_permitted_cross_domain": xpcd_result,
            "has_frame_busting_js": has_frame_bust,
        }

        if has_frame_bust:
            signals.extend(bust_patterns[:5])
            evidence["frame_bust_patterns"] = bust_patterns[:5]

        if missing_xfo:
            signals.append("missing_x_frame_options")
        if missing_csp_frame:
            signals.append("missing_csp_frame_ancestors")
        if permissive_csp:
            signals.append("permissive_frame_ancestors")
        if deprecated_xfo:
            signals.append("deprecated_x_frame_options_allow_from")
        if xpcd_result.get("issues"):
            signals.extend(xpcd_result["issues"])

        if is_sensitive and (missing_xfo or missing_csp_frame):
            severity = "high"
            title = f"Sensitive endpoint missing clickjacking protection: {url}"
            explanation = (
                f"Sensitive endpoint '{url}' lacks proper anti-clickjacking "
                f"protections. X-Frame-Options: {xfo_result.get('value') or 'missing'}, "
                f"CSP frame-ancestors: {csp_result.get('value') or 'missing'}. "
                f"This endpoint could be embedded in a malicious iframe for clickjacking."
            )
        elif missing_xfo and missing_csp_frame:
            severity = "medium"
            title = f"Endpoint missing all clickjacking protections: {url}"
            explanation = (
                f"Endpoint '{url}' is missing both X-Frame-Options and "
                f"CSP frame-ancestors protections. It can potentially be "
                f"embedded in an iframe on an attacker-controlled page."
            )
        elif permissive_csp:
            severity = "low"
            title = f"Overly permissive frame-ancestors policy: {url}"
            explanation = (
                f"Endpoint '{url}' has a CSP frame-ancestors directive that "
                f"is overly permissive: {csp_result.get('value')}. "
                f"Consider restricting to specific trusted origins."
            )
        elif deprecated_xfo:
            severity = "low"
            title = f"Deprecated X-Frame-Options ALLOW-FROM: {url}"
            explanation = (
                f"Endpoint '{url}' uses the deprecated ALLOW-FROM value for "
                f"X-Frame-Options which is not supported by modern browsers. "
                f"Use CSP frame-ancestors instead."
            )
        else:
            continue

        finding = _build_finding(
            url=url,
            severity=severity,
            title=title,
            category="clickjacking",
            signals=signals,
            evidence=evidence,
            explanation=explanation,
            status_code=status_code,
        )
        findings.append(finding)

        if missing_xfo or missing_csp_frame:
            unprotected_urls.append((url, resp, headers))

    active_probed = 0
    for url, resp, headers in unprotected_urls:
        if active_probed >= limit:
            break
        if not url.startswith(("http://", "https://")):
            continue

        probe_result = _safe_request(url, timeout=8)
        if not probe_result.get("success"):
            continue
        active_probed += 1

        probe_headers = {str(k).lower(): str(v) for k, v in probe_result.get("headers", {}).items()}
        probe_body = str(probe_result.get("body") or "")[:5000]
        probe_status = probe_result.get("status", 0)

        has_bust, bust_patterns = _has_frame_busting_js(probe_body)
        probe_xfo = _check_x_frame_options(probe_headers)
        probe_csp = _check_csp_frame_ancestors(probe_headers)

        if has_bust:
            continue

        is_sensitive = _is_sensitive_endpoint(url)
        severity = "high" if is_sensitive else "medium"

        signals = ["active_probe_confirms_no_protection"]
        if probe_xfo.get("issues"):
            signals.extend(probe_xfo["issues"][:3])
        if probe_csp.get("issues"):
            signals.extend(probe_csp["issues"][:3])

        evidence = {
            "probe_status": probe_status,
            "probe_x_frame_options": probe_xfo,
            "probe_csp_frame_ancestors": probe_csp,
            "has_frame_busting_js": has_bust,
            "original_response_status": resp.get("status_code"),
        }

        finding = _build_finding(
            url=url,
            severity=severity,
            title=f"Active probe confirms clickjacking vulnerability: {url}",
            category="clickjacking",
            signals=signals,
            evidence=evidence,
            explanation=(
                f"Active probe to '{url}' confirmed the endpoint lacks "
                f"anti-clickjacking protections. Status: {probe_status}. "
                f"X-Frame-Options: {probe_xfo.get('value') or 'missing'}, "
                f"CSP frame-ancestors: {probe_csp.get('value') or 'missing'}. "
                f"{'This is a sensitive endpoint.' if is_sensitive else ''}"
            ),
            status_code=probe_status,
        )
        findings.append(finding)

    return findings[:100]
