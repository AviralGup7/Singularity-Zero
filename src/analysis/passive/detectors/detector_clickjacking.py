"""Clickjacking vulnerability detector for OWASP A05: Security Misconfiguration.

Passively analyzes HTTP responses for clickjacking vulnerabilities including
missing or weak X-Frame-Options, missing CSP frame-ancestors, absent frame-busting
JavaScript, and iframe-susceptible endpoint patterns.
"""

import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_signature,
    is_auth_flow_endpoint,
    is_noise_url,
    normalized_confidence,
)

_IFRAME_FRIENDLY_PATHS = (
    "/login",
    "/signin",
    "/auth",
    "/oauth",
    "/authorize",
    "/payment",
    "/checkout",
    "/pay",
    "/billing",
    "/card",
    "/account",
    "/profile",
    "/settings",
    "/preferences",
    "/transfer",
    "/withdraw",
    "/deposit",
    "/donate",
    "/delete",
    "/remove",
    "/disable",
    "/deactivate",
    "/admin",
    "/dashboard",
    "/console",
    "/manage",
    "/api-key",
    "/token",
    "/session",
    "/password",
    "/confirm",
    "/verify",
    "/approve",
)

_FRAME_BUSTING_JS = re.compile(
    r"(?:if\s*\(\s*(?:top|self|parent|window\.top)\s*!==?\s*(?:self|window|top|parent)\s*\)"
    r"|(?:top|self|parent|window\.top)\s*===?\s*(?:self|window|top|parent)\s*\?"
    r"|window\.top\s*!==?\s*window\s*\{"
    r"|if\s*\(\s*top\s*!=\s*self\s*\)"
    r"|if\s*\(\s*top\.location\s*!=\s*location\s*\)"
    r"|top\.location\s*=\s*self\.location"
    r"|top\.location\s*=\s*location"
    r"|break\s*;\s*\}"
    r"|framebust|frame.?buster|frame.?killer)",
    re.IGNORECASE,
)

_CSP_FRAME_ANCESTORS_WILDCARD = re.compile(r"frame-ancestors\s+[^;]*\*", re.IGNORECASE)
_CSP_FRAME_ANCESTORS_RE = re.compile(r"frame-ancestors\s+([^;]*)", re.IGNORECASE)

_PERMISSIVE_ORIGINS = {"*", "data:", "blob:", "about:"}


def _check_x_frame_options(headers: dict[str, str]) -> list[str]:
    """Check X-Frame-Options header for missing or weak values."""
    signals: list[str] = []
    xfo = headers.get("x-frame-options", "").strip()

    if not xfo:
        signals.append("missing_x_frame_options")
        return signals

    xfo_lower = xfo.lower()
    if xfo_lower == "deny":
        signals.append("xfo_deny")
    elif xfo_lower == "sameorigin":
        signals.append("xfo_sameorigin")
    elif xfo_lower.startswith("allow-from"):
        origin_part = xfo[10:].strip()
        if not origin_part:
            signals.append("weak_xfo_allow_from_no_origin")
        else:
            signals.append(f"xfo_allow_from:{origin_part}")
    else:
        signals.append(f"unusual_xfo_value:{xfo}")

    return signals


def _check_csp_frame_ancestors(headers: dict[str, str]) -> list[str]:
    """Check CSP frame-ancestors directive for missing or weak values."""
    signals: list[str] = []
    csp = headers.get("content-security-policy", "")
    csp_report = headers.get("content-security-policy-report-only", "")
    combined = csp or csp_report

    if not combined:
        signals.append("missing_csp_frame_ancestors")
        return signals

    match = _CSP_FRAME_ANCESTORS_RE.search(combined)
    if not match:
        signals.append("missing_csp_frame_ancestors")
        return signals

    ancestors = match.group(1).strip()
    if not ancestors:
        signals.append("empty_csp_frame_ancestors")
        return signals

    if _CSP_FRAME_ANCESTORS_WILDCARD.search(combined):
        signals.append("wildcard_csp_frame_ancestors")
        return signals

    ancestor_values = set(ancestors.lower().split())
    permissive_found = ancestor_values & _PERMISSIVE_ORIGINS
    if permissive_found:
        signals.append(f"permissive_csp_frame_ancestors:{','.join(sorted(permissive_found))}")
        return signals

    signals.append(f"csp_frame_ancestors_set:{ancestors[:100]}")
    return signals


def _check_frame_busting(body: str) -> list[str]:
    """Check response body for frame-busting JavaScript."""
    signals: list[str] = []

    if _FRAME_BUSTING_JS.search(body):
        signals.append("frame_busting_js_present")
    else:
        signals.append("no_frame_busting_js")

    return signals


def _check_iframe_susceptible_endpoint(url: str) -> list[str]:
    """Check if URL path suggests an iframe-susceptible endpoint."""
    signals: list[str] = []
    path = urlparse(url).path.lower()

    if any(kw in path for kw in _IFRAME_FRIENDLY_PATHS):
        signals.append("iframe_susceptible_endpoint")

        if is_auth_flow_endpoint(url):
            signals.append("auth_flow_iframe_target")

        if any(
            kw in path
            for kw in (
                "/payment",
                "/checkout",
                "/pay",
                "/billing",
                "/card",
                "/transfer",
                "/withdraw",
            )
        ):
            signals.append("financial_iframe_target")

        if any(kw in path for kw in ("/admin", "/dashboard", "/console", "/manage")):
            signals.append("admin_iframe_target")

    return signals


def _calculate_severity(signals: list[str]) -> str:
    critical_indicators = {
        "wildcard_csp_frame_ancestors",
        "permissive_csp_frame_ancestors:",
    }
    high_indicators = {
        "missing_x_frame_options",
        "missing_csp_frame_ancestors",
        "weak_xfo_allow_from_no_origin",
        "auth_flow_iframe_target",
        "financial_iframe_target",
    }
    medium_indicators = {
        "no_frame_busting_js",
        "iframe_susceptible_endpoint",
        "admin_iframe_target",
    }

    for signal in signals:
        if signal in critical_indicators or any(
            signal.startswith(ind) for ind in critical_indicators
        ):
            return "high"
    for signal in signals:
        if signal in high_indicators or any(signal.startswith(ind) for ind in high_indicators):
            return "high"
    for signal in signals:
        if signal in medium_indicators or any(signal.startswith(ind) for ind in medium_indicators):
            return "medium"
    return "low"


def _calculate_risk_score(signals: list[str]) -> int:
    score = 0
    severity_scores: dict[str, int] = {
        "missing_x_frame_options": 5,
        "missing_csp_frame_ancestors": 4,
        "wildcard_csp_frame_ancestors": 8,
        "weak_xfo_allow_from_no_origin": 6,
        "auth_flow_iframe_target": 6,
        "financial_iframe_target": 7,
        "admin_iframe_target": 5,
        "no_frame_busting_js": 3,
        "iframe_susceptible_endpoint": 3,
    }

    for signal in signals:
        if signal in severity_scores:
            score += severity_scores[signal]
        elif signal.startswith("permissive_csp_frame_ancestors:"):
            score += 7
        elif signal.startswith("xfo_allow_from:"):
            score += 4
        elif signal.startswith("csp_frame_ancestors_set:"):
            score += 1
        elif signal.startswith("unusual_xfo_value:"):
            score += 2
        elif signal.startswith("xfo_deny"):
            score = max(0, score - 2)
        elif signal.startswith("xfo_sameorigin"):
            score = max(0, score - 1)

    return min(max(score, 0), 20)


def clickjacking_detector(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Detect clickjacking vulnerabilities passively.

    Analyzes responses for:
    - Missing X-Frame-Options header
    - Weak X-Frame-Options (ALLOW-FROM with no origin)
    - Missing CSP frame-ancestors directive
    - Weak CSP frame-ancestors (* or too permissive)
    - Absence of frame-busting JavaScript
    - Iframe-susceptible endpoints (login forms, payment forms, admin panels)
    - UI element patterns susceptible to clickjacking

    Args:
        urls: Set of URLs to analyze.
        responses: List of HTTP response dicts.
        limit: Maximum number of findings to return.

    Returns:
        List of clickjacking findings sorted by risk score.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
        body = str(response.get("body_text") or "")

        signals: list[str] = []
        signals.extend(_check_x_frame_options(headers))
        signals.extend(_check_csp_frame_ancestors(headers))
        signals.extend(_check_frame_busting(body))
        signals.extend(_check_iframe_susceptible_endpoint(url))

        has_protection = any(s in signals for s in ("xfo_deny", "xfo_sameorigin"))
        has_csp_protection = any(s.startswith("csp_frame_ancestors_set:") for s in signals)

        if (
            has_protection
            and has_csp_protection
            and not any(
                s in signals for s in ("iframe_susceptible_endpoint", "no_frame_busting_js")
            )
        ):
            continue

        missing_protections = [
            s
            for s in signals
            if s.startswith(("missing_", "no_", "weak_", "wildcard_", "permissive_"))
        ]
        if not missing_protections and not any(s.startswith("iframe_susceptible") for s in signals):
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(signals)
        risk_score = _calculate_risk_score(signals)
        confidence = normalized_confidence(
            base=0.48,
            score=risk_score,
            signals=signals,
            cap=0.92,
        )

        title_parts: list[str] = []
        if "missing_x_frame_options" in signals:
            title_parts.append("Missing X-Frame-Options Header")
        if "missing_csp_frame_ancestors" in signals:
            title_parts.append("Missing CSP frame-ancestors Directive")
        if "wildcard_csp_frame_ancestors" in signals:
            title_parts.append("Wildcard CSP frame-ancestors")
        if any(s.startswith("permissive_csp_frame_ancestors:") for s in signals):
            title_parts.append("Permissive CSP frame-ancestors")
        if "weak_xfo_allow_from_no_origin" in signals:
            title_parts.append("Weak X-Frame-Options ALLOW-FROM")
        if "no_frame_busting_js" in signals:
            title_parts.append("No Frame-Busting JavaScript")
        if "auth_flow_iframe_target" in signals:
            title_parts.append("Auth Flow Susceptible to Clickjacking")
        if "financial_iframe_target" in signals:
            title_parts.append("Financial Endpoint Susceptible to Clickjacking")
        if "admin_iframe_target" in signals:
            title_parts.append("Admin Panel Susceptible to Clickjacking")

        title = "; ".join(title_parts) if title_parts else "Clickjacking Surface Detected"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": sorted(signals),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    findings.sort(key=lambda item: (-item["risk_score"], item["url"]))
    return findings[:limit]
