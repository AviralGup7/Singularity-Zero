"""Open redirect attack surface detector for OWASP A01: Broken Access Control.

Passively analyzes URLs and HTTP responses for open redirect vulnerabilities,
including redirect parameters, meta refresh tags, JavaScript redirects,
and Location header issues.
"""

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_signature,
    is_noise_url,
    normalized_confidence,
)

_REDIRECT_PARAM_NAMES = {
    "action",
    "assertionconsumerurl",
    "back",
    "callback",
    "checkout_url",
    "continue",
    "dest",
    "destination",
    "externallink",
    "forward",
    "forward_url",
    "from",
    "goto",
    "image_url",
    "link",
    "login_redirect",
    "next",
    "next_url",
    "nexturl",
    "out",
    "path",
    "post_login_redirect",
    "redir",
    "redirect",
    "redirect_to",
    "redirect_url",
    "redirect_uri",
    "referer",
    "relaystate",
    "return",
    "return_path",
    "return_to",
    "returnURL",
    "returnUrl",
    "rurl",
    "samlrelaystate",
    "state",
    "target",
    "to",
    "uri",
    "url",
    "url_to",
    "view",
}

_EXTERNAL_DOMAIN_RE = re.compile(
    r"https?://(?!(?:localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0))",
    re.IGNORECASE,
)

_META_REFRESH_RE = re.compile(
    r'<meta\s+[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*["\']?([^"\'>\s]+)',
    re.IGNORECASE,
)

_JS_REDIRECT_RE = re.compile(
    r'(?:window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']|'
    r'location\.(?:href|replace)\s*=\s*["\']([^"\']+)["\']|'
    r'window\.open\s*\(\s*["\']([^"\']+)["\']|'
    r'document\.location\s*=\s*["\']([^"\']+)["\']|'
    r'self\.location\s*=\s*["\']([^"\']+)["\']|'
    r'top\.location\s*=\s*["\']([^"\']+)["\'])',
    re.IGNORECASE,
)

_JS_REDIRECT_VAR_RE = re.compile(
    r"(?:window\.location|location\.href|location\.replace|document\.location)\s*=\s*([a-zA-Z_$][\w$]*)",
    re.IGNORECASE,
)

_OPEN_REDIRECT_ERROR_RE = re.compile(
    r"(?:open\s*redirect|redirect\s*(?:not\s*)?allowed|invalid\s*redirect|"
    r"redirect\s*blocked|redirect\s*target|unsafe\s*redirect|"
    r"redirect\s*validation|redirect\s*url\s*(?:is\s*)?invalid)",
    re.IGNORECASE,
)

_IP_BYPASS_RE = re.compile(
    r"(?:0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3})"
    r"|"
    r"(?:0[xX][0-9a-fA-F]{1,2}\.0[xX][0-9a-fA-F]{1,2}\.0[xX][0-9a-fA-F]{1,2}\.0[xX][0-9a-fA-F]{1,2})"
    r"|"
    r"(?:0[xX][0-9a-fA-F]{8})"
    r"|"
    r"(?<![.\d])(?:\d{9,10})(?![.\d])"
    r"|"
    r"(?:\[::[0-9a-fA-F.:]+\])"
    r"|"
    r"(?:%E3%80%82|%EF%BC%8E|%3C%2F%2F)"
    r"|"
    r"(?:http%3[Aa]%2[Ff]%2[Ff])"
    r"|"
    r"(?:\x00|\x20|%00|\\x00|\\x20)https?://"
    r"|"
    r"(?:%252[Ff]|%250[AaDd])"
    r"|"
    r"(?:。|%uFF0E)",
    re.IGNORECASE,
)

_GOOGLE_REFLECTION_RE = re.compile(
    r"(?:google\.com|www\.google\.com|google%2Ecom|google%E3%80%82com)",
    re.IGNORECASE,
)

_GOOGLE_IN_SCRIPT_RE = re.compile(
    r"<script[^>]*>.*?google\.com.*?</script>",
    re.IGNORECASE | re.DOTALL,
)

_GOOGLE_META_REFRESH_RE = re.compile(
    r'<meta\s+[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*google\.com',
    re.IGNORECASE,
)

_DOM_SINK_RE = re.compile(
    r"(?:window\.location(?:\.href)?\s*[:=]|"
    r"location\.(?:href|replace|hash|search|pathname)\s*[:=]|"
    r"window\.open\s*\(|"
    r"document\.(?:URL|referrer|documentURI|baseURI|cookie)\s*[:=]|"
    r"eval\s*\(|"
    r"setTimeout\s*\(|"
    r"setInterval\s*\(|"
    r"document\.(?:write|writeln)\s*\(|"
    r"\w+\.(?:innerHTML|outerHTML)\s*=|"
    r"insertAdjacentHTML\s*\()",
    re.IGNORECASE,
)


def _check_ip_bypass(url: str) -> list[str]:
    """Check redirect parameter values for IP encoding bypass patterns."""
    signals: list[str] = []
    parsed = urlparse(url)

    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if value and _IP_BYPASS_RE.search(value):
            bypass_name = key.lower().strip()
            signals.append(f"ip_bypass_detected:{bypass_name}")

    return signals


def _check_google_reflection(response: dict[str, Any]) -> list[str]:
    """Check if response contains google.com indicating redirect was followed."""
    signals: list[str] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    body = str(response.get("body_text") or "")

    location = headers.get("location", "")
    if _GOOGLE_REFLECTION_RE.search(location):
        signals.append("google_reflection_location_header")

    if _GOOGLE_IN_SCRIPT_RE.search(body):
        signals.append("google_reflection_script_tag")

    if _GOOGLE_META_REFRESH_RE.search(body):
        signals.append("google_reflection_meta_refresh")

    if _GOOGLE_REFLECTION_RE.search(body) and not _GOOGLE_IN_SCRIPT_RE.search(body):
        signals.append("google_reflection_body")

    return signals


def _check_dom_sinks(response: dict[str, Any]) -> list[str]:
    """Scan response body for dangerous DOM manipulation patterns."""
    signals: list[str] = []
    body = str(response.get("body_text") or "")

    sinks_found = set()
    for match in _DOM_SINK_RE.finditer(body):
        found = match.group(0).strip().lower()
        if "window.location" in found or "location.href" in found:
            sinks_found.add("location")
        if "location.replace" in found:
            sinks_found.add("location_replace")
        if "window.open" in found:
            sinks_found.add("window_open")
        if "location.hash" in found:
            sinks_found.add("location_hash")
        if "location.search" in found:
            sinks_found.add("location_search")
        if "location.pathname" in found:
            sinks_found.add("location_pathname")
        if "document.url" in found:
            sinks_found.add("document_url")
        if "document.referrer" in found:
            sinks_found.add("document_referrer")
        if "document.documenturi" in found:
            sinks_found.add("document_documenturi")
        if "document.baseuri" in found:
            sinks_found.add("document_baseuri")
        if "document.cookie" in found:
            sinks_found.add("document_cookie")
        if "eval" in found:
            sinks_found.add("eval")
        if "settimeout" in found:
            sinks_found.add("setTimeout")
        if "setinterval" in found:
            sinks_found.add("setInterval")
        if "document.write" in found:
            sinks_found.add("document_write")
        if "document.writeln" in found:
            sinks_found.add("document_writeln")
        if "innerhtml" in found:
            sinks_found.add("innerHTML")
        if "outerhtml" in found:
            sinks_found.add("outerHTML")
        if "insertadjacenthtml" in found:
            sinks_found.add("insertAdjacentHTML")

    for sink in sinks_found:
        signals.append(f"dom_sink:{sink}")

    return signals


def _check_redirect_params(url: str) -> list[str]:
    """Check URL query parameters for redirect-related parameters."""
    signals: list[str] = []
    parsed = urlparse(url)

    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        key_lower = key.lower().strip()
        if key_lower in _REDIRECT_PARAM_NAMES:
            signals.append(f"redirect_param:{key_lower}")

            if value and _EXTERNAL_DOMAIN_RE.match(value):
                signals.append(f"external_redirect_target:{key_lower}")
            elif value and _IP_BYPASS_RE.search(value):
                signals.append(f"ip_bypass_redirect:{key_lower}")
            elif value and value.startswith("//"):
                signals.append(f"protocol_relative_redirect:{key_lower}")
            elif value and value.startswith(("http://", "https://")):
                signals.append(f"absolute_redirect_target:{key_lower}")

    return signals


def _check_meta_refresh(response: dict[str, Any]) -> list[str]:
    """Check response body for meta refresh tags with external URLs."""
    signals: list[str] = []
    body = str(response.get("body_text") or "")

    matches = _META_REFRESH_RE.findall(body)
    for match in matches[:5]:
        url_val = match.strip().strip("'\"")
        if _EXTERNAL_DOMAIN_RE.match(url_val):
            signals.append(f"meta_refresh_external:{url_val[:80]}")
        elif url_val:
            signals.append("meta_refresh_redirect")

    return signals


def _check_js_redirects(response: dict[str, Any]) -> list[str]:
    """Check response body for JavaScript-based redirects."""
    signals: list[str] = []
    body = str(response.get("body_text") or "")

    js_matches = _JS_REDIRECT_RE.findall(body)
    for match_tuple in js_matches[:5]:
        for url_val in match_tuple:
            if url_val:
                url_val = url_val.strip().strip("'\"")
                if _EXTERNAL_DOMAIN_RE.match(url_val):
                    signals.append(f"js_redirect_external:{url_val[:80]}")
                elif url_val:
                    signals.append("js_redirect_detected")
                break

    var_matches = _JS_REDIRECT_VAR_RE.findall(body)
    if var_matches:
        signals.append("js_redirect_variable_based")

    return signals


def _check_location_header(response: dict[str, Any]) -> list[str]:
    """Check Location header for user-controllable redirect values."""
    signals: list[str] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    location = headers.get("location", "")

    if location:
        signals.append("location_header_present")

        if _EXTERNAL_DOMAIN_RE.match(location):
            signals.append("location_header_external")

        if any(param in location.lower() for param in _REDIRECT_PARAM_NAMES):
            signals.append("location_header_param_reflection")

        if location.startswith("//"):
            signals.append("location_header_protocol_relative")

    return signals


def _check_open_redirect_errors(response: dict[str, Any]) -> list[str]:
    """Check response for open redirect error patterns."""
    signals: list[str] = []
    body = str(response.get("body_text") or "")

    if _OPEN_REDIRECT_ERROR_RE.search(body):
        signals.append("open_redirect_error_in_response")

    return signals


def _calculate_severity(signals: list[str]) -> str:
    critical_indicators = {
        "js_redirect_external:",
        "meta_refresh_external:",
    }
    high_indicators = {
        "external_redirect_target:",
        "location_header_external",
        "open_redirect_error_in_response",
        "ip_bypass_redirect:",
        "google_reflection_location_header",
    }
    medium_indicators = {
        "absolute_redirect_target:",
        "protocol_relative_redirect:",
        "location_header_protocol_relative",
        "location_header_param_reflection",
        "js_redirect_variable_based",
        "meta_refresh_redirect",
        "google_reflection_script_tag",
        "google_reflection_meta_refresh",
        "google_reflection_body",
    }

    for signal in signals:
        if any(signal.startswith(ind) for ind in critical_indicators):
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
        "location_header_external": 7,
        "open_redirect_error_in_response": 6,
        "location_header_protocol_relative": 5,
        "location_header_param_reflection": 6,
        "js_redirect_variable_based": 4,
        "meta_refresh_redirect": 4,
        "location_header_present": 2,
    }

    for signal in signals:
        if signal in severity_scores:
            score += severity_scores[signal]
        elif signal.startswith("external_redirect_target:"):
            score += 7
        elif signal.startswith("ip_bypass_redirect:") or signal.startswith("ip_bypass_detected:"):
            score += 7
        elif signal.startswith("absolute_redirect_target:"):
            score += 5
        elif signal.startswith("protocol_relative_redirect:"):
            score += 5
        elif signal.startswith("js_redirect_external:"):
            score += 8
        elif signal.startswith("js_redirect_detected"):
            score += 4
        elif signal.startswith("meta_refresh_external:"):
            score += 8
        elif signal.startswith("redirect_param:"):
            score += 3
        elif signal.startswith("google_reflection_"):
            score += 6
        elif signal.startswith("dom_sink:"):
            score += 4

    return min(score, 20)


def open_redirect_detector(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Detect open redirect attack surfaces passively.

    Analyzes URLs and responses for:
    - Redirect-related parameters (url, redirect, redirect_uri, return, next, etc.)
    - URL-like parameter values pointing to external domains
    - Meta refresh tags with external URLs in response bodies
    - JavaScript-based redirects (window.location, location.href)
    - Location headers with user-controllable values
    - Open redirect error patterns in responses

    Args:
        urls: Set of URLs to analyze.
        responses: List of HTTP response dicts.
        limit: Maximum number of findings to return.

    Returns:
        List of open redirect findings sorted by risk score.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url in sorted(urls):
        if is_noise_url(url):
            continue

        signals = _check_redirect_params(url)
        signals.extend(_check_ip_bypass(url))
        if not signals:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(signals)
        risk_score = _calculate_risk_score(signals)
        confidence = normalized_confidence(
            base=0.45,
            score=risk_score,
            signals=signals,
            cap=0.90,
        )

        title_parts: list[str] = []
        if any(s.startswith("external_redirect_target:") for s in signals):
            title_parts.append("External Redirect Target in Parameter")
        if any(s.startswith("ip_bypass") for s in signals):
            title_parts.append("IP Bypass Encoding Detected in Redirect Parameter")
        if any(s.startswith("absolute_redirect_target:") for s in signals):
            title_parts.append("Absolute URL in Redirect Parameter")
        if any(s.startswith("protocol_relative_redirect:") for s in signals):
            title_parts.append("Protocol-Relative Redirect Target")
        if any(s.startswith("redirect_param:") for s in signals):
            title_parts.append("Redirect Parameter Detected")

        title = "; ".join(title_parts) if title_parts else "Open Redirect Surface Detected"

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

    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        resp_signals: list[str] = []
        resp_signals.extend(_check_meta_refresh(response))
        resp_signals.extend(_check_js_redirects(response))
        resp_signals.extend(_check_location_header(response))
        resp_signals.extend(_check_open_redirect_errors(response))
        resp_signals.extend(_check_google_reflection(response))
        resp_signals.extend(_check_dom_sinks(response))

        if not resp_signals:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(resp_signals)
        risk_score = _calculate_risk_score(resp_signals)
        confidence = normalized_confidence(
            base=0.45,
            score=risk_score,
            signals=resp_signals,
            cap=0.92,
        )

        resp_title_parts: list[str] = []
        if any(s.startswith("js_redirect_external:") for s in resp_signals):
            resp_title_parts.append("JavaScript Redirect to External URL")
        if any(s.startswith("meta_refresh_external:") for s in resp_signals):
            resp_title_parts.append("Meta Refresh to External URL")
        if "location_header_external" in resp_signals:
            resp_title_parts.append("Location Header Points to External Domain")
        if "open_redirect_error_in_response" in resp_signals:
            resp_title_parts.append("Open Redirect Error Detected")
        if "js_redirect_variable_based" in resp_signals:
            resp_title_parts.append("Variable-Based JavaScript Redirect")
        if "location_header_param_reflection" in resp_signals:
            resp_title_parts.append("Location Header Reflects Parameters")
        if any(s.startswith("google_reflection") for s in resp_signals):
            resp_title_parts.append("Google Reflection Detected (Open Redirect)")
        if any(s.startswith("dom_sink:") for s in resp_signals):
            resp_title_parts.append("Dangerous DOM Redirect Sinks Detected")

        title = (
            "; ".join(resp_title_parts)
            if resp_title_parts
            else "Open Redirect Response Issue Detected"
        )

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": sorted(resp_signals),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    findings.sort(key=lambda item: (-item["risk_score"], item["url"]))
    return findings[:limit]
