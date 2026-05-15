"""Vulnerable component detector for OWASP A06: Vulnerable and Outdated Components.

Passively analyzes HTTP responses for version disclosure, technology fingerprinting,
deprecated API endpoints, known vulnerable framework signatures, and default
configuration indicators.
"""

import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_signature,
    is_noise_url,
    normalized_confidence,
)

_SERVER_VERSION_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)^Apache/(\d+\.\d+[\.\d]*)", "Apache", "Web server version disclosure"),
    (r"(?i)^nginx/(\d+\.\d+[\.\d]*)", "Nginx", "Web server version disclosure"),
    (r"(?i)^Microsoft-IIS/(\d+\.\d+)", "Microsoft-IIS", "Web server version disclosure"),
    (r"(?i)^lighttpd/(\d+\.\d+[\.\d]*)", "Lighttpd", "Web server version disclosure"),
    (r"(?i)^Caddy/(\d+\.\d+[\.\d]*)", "Caddy", "Web server version disclosure"),
    (r"(?i)^Tomcat[/-](\d+\.\d+[\.\d]*)", "Apache Tomcat", "Application server version disclosure"),
    (r"(?i)^Jetty[/-](\d+\.\d+[\.\d]*)", "Jetty", "Application server version disclosure"),
    (r"(?i)^gunicorn/(\d+\.\d+[\.\d]*)", "Gunicorn", "Application server version disclosure"),
    (r"(?i)^OpenResty/(\d+\.\d+[\.\d]*)", "OpenResty", "Web server version disclosure"),
]

_POWERED_BY_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)PHP/(\d+\.\d+[\.\d]*)", "PHP", "Backend language version disclosure"),
    (r"(?i)Express", "Express", "Node.js framework disclosure"),
    (r"(?i)ASP\.NET", "ASP.NET", "Microsoft framework disclosure"),
    (r"(?i)Next\.?JS", "Next.js", "React framework disclosure"),
    (r"(?i)Spring", "Spring Framework", "Java framework disclosure"),
    (r"(?i)Django/(\d+\.\d+[\.\d]*)", "Django", "Python framework disclosure"),
    (r"(?i)Flask", "Flask", "Python framework disclosure"),
    (r"(?i)FastAPI", "FastAPI", "Python framework disclosure"),
    (r"(?i)Laravel", "Laravel", "PHP framework disclosure"),
    (r"(?i)Ruby on Rails", "Ruby on Rails", "Ruby framework disclosure"),
    (r"(?i)WordPress/(\d+\.\d+[\.\d]*)", "WordPress", "CMS version disclosure"),
]

_KNOWN_VULNERABLE_VERSIONS: list[tuple[str, str, str, str]] = [
    (r"Apache/2\.2\.\d+", "Apache 2.2.x", "high", "End-of-life Apache version with known CVEs"),
    (r"nginx/1\.[0-9]\.", "Nginx 1.x < 1.10", "high", "End-of-life Nginx version"),
    (r"Microsoft-IIS/6\.0", "IIS 6.0", "critical", "End-of-life IIS with critical vulnerabilities"),
    (r"Microsoft-IIS/7\.0", "IIS 7.0", "high", "End-of-life IIS version"),
    (r"Microsoft-IIS/7\.5", "IIS 7.5", "high", "End-of-life IIS version"),
    (r"Tomcat/8\.", "Tomcat 8.x", "medium", "Outdated Tomcat version"),
    (r"Tomcat/7\.", "Tomcat 7.x", "high", "End-of-life Tomcat version"),
    (r"PHP/5\.[0-4]\.", "PHP 5.0-5.4", "critical", "End-of-life PHP with critical vulnerabilities"),
    (r"PHP/5\.5\.", "PHP 5.5", "high", "End-of-life PHP version"),
    (r"PHP/5\.6\.", "PHP 5.6", "medium", "End-of-life PHP version"),
    (r"Django/1\.", "Django 1.x", "critical", "End-of-life Django with critical vulnerabilities"),
    (r"Django/2\.[01]\.", "Django 2.0-2.1", "high", "End-of-life Django version"),
    (r"Rails/3\.", "Rails 3.x", "critical", "End-of-life Rails with critical vulnerabilities"),
    (r"Rails/4\.", "Rails 4.x", "high", "End-of-life Rails version"),
    (
        r"Laravel/5\.[0-4]\.",
        "Laravel 5.0-5.4",
        "high",
        "Outdated Laravel with known vulnerabilities",
    ),
    (r"WordPress/4\.", "WordPress 4.x", "high", "End-of-life WordPress version"),
]

_DEPRECATED_API_PATTERNS = re.compile(
    r"(?:/v1/|/v0/|/api/v1/|/api/v0/|/old/|/legacy/|/deprecated/|/api/1\.0/|/api/0\.\d/)",
    re.IGNORECASE,
)

_DEFAULT_CONFIG_INDICATORS = re.compile(
    r"(?:default\s*password|admin\s*:\s*admin|test\s*:\s*test|demo\s*mode|"
    r"sample\s*data|placeholder\s*content|welcome\s*page|default\s*page|"
    r"it\s*works|welcome\s*to\s*(?:nginx|apache|iis)|"
    r"tomcat\s*manager|default\s*installation|out\s*of\s*the\s*box)",
    re.IGNORECASE,
)

_FRAMEWORK_VERSION_HEADERS = {
    "x-aspnet-version": ("ASP.NET", "Microsoft framework version disclosure"),
    "x-aspnetmvc-version": ("ASP.NET MVC", "Microsoft MVC framework version disclosure"),
    "x-runtime": ("Ruby on Rails", "Ruby/Rails runtime disclosure"),
    "x-rack-version": ("Rack", "Ruby middleware version disclosure"),
    "x-generator": ("CMS/Generator", "Content management system disclosure"),
    "x-powered-by": ("X-Powered-By", "Technology stack disclosure"),
}


def _check_server_version(response: dict[str, Any]) -> list[str]:
    """Check Server header for version disclosure."""
    signals: list[str] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    server_header = headers.get("server", "")

    if not server_header:
        return signals

    for pattern, tech, desc in _SERVER_VERSION_PATTERNS:
        match = re.search(pattern, server_header)
        if match:
            version = match.group(1) if match.lastindex else ""
            signals.append(f"server_version_disclosure:{tech}:{version}")
            break

    return signals


def _check_powered_by(response: dict[str, Any]) -> list[str]:
    """Check X-Powered-By header for framework version disclosure."""
    signals: list[str] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    powered_by = headers.get("x-powered-by", "")

    if not powered_by:
        return signals

    for pattern, tech, desc in _POWERED_BY_PATTERNS:
        match = re.search(pattern, powered_by)
        if match:
            version = match.group(1) if match.lastindex else ""
            signals.append(f"powered_by_disclosure:{tech}:{version}")
            break

    return signals


def _check_framework_headers(response: dict[str, Any]) -> list[str]:
    """Check for framework-specific version headers."""
    signals: list[str] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}

    for header_name, (tech, desc) in _FRAMEWORK_VERSION_HEADERS.items():
        if header_name in headers:
            value = headers[header_name]
            signals.append(f"framework_header:{tech}:{value[:50]}")

    return signals


def _check_vulnerable_versions(response: dict[str, Any]) -> list[str]:
    """Check for known vulnerable version patterns."""
    signals: list[str] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    body = str(response.get("body_text") or "")

    server_header = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    combined = f"{server_header} {powered_by} {body[:5000]}"

    for pattern, component, severity, desc in _KNOWN_VULNERABLE_VERSIONS:
        match = re.search(pattern, combined)
        if match:
            signals.append(f"vulnerable_version:{component}:{severity}")

    return signals


def _check_deprecated_endpoints(url: str) -> list[str]:
    """Check for deprecated API endpoint patterns."""
    signals: list[str] = []
    path = urlparse(url).path

    if _DEPRECATED_API_PATTERNS.search(path):
        signals.append("deprecated_api_endpoint")

        if "/v1/" in path or "/api/v1/" in path:
            signals.append("api_v1_endpoint")
        elif "/v0/" in path or "/api/v0/" in path:
            signals.append("api_v0_endpoint")
        elif "/old/" in path or "/legacy/" in path:
            signals.append("legacy_endpoint")
        elif "/deprecated/" in path:
            signals.append("explicitly_deprecated_endpoint")

    return signals


def _check_default_config(response: dict[str, Any]) -> list[str]:
    """Check for default configuration indicators."""
    signals: list[str] = []
    body = str(response.get("body_text") or "")

    if _DEFAULT_CONFIG_INDICATORS.search(body):
        signals.append("default_configuration_detected")

    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}

    if headers.get("x-debug", "").lower() in ("true", "1", "yes", "on"):
        signals.append("debug_mode_enabled")

    if "x-environment" in headers:
        env_val = headers["x-environment"].lower()
        if env_val in ("development", "dev", "debug", "staging", "test"):
            signals.append(f"non_production_environment:{env_val}")

    return signals


def _calculate_severity(signals: list[str]) -> str:
    critical_indicators = {
        "debug_mode_enabled",
    }
    high_indicators = {
        "default_configuration_detected",
        "non_production_environment:",
    }
    medium_indicators = {
        "deprecated_api_endpoint",
        "legacy_endpoint",
        "explicitly_deprecated_endpoint",
    }

    for signal in signals:
        if signal in critical_indicators:
            return "critical"
    for signal in signals:
        if signal in high_indicators or any(signal.startswith(ind) for ind in high_indicators):
            return "high"
    for signal in signals:
        if signal in medium_indicators or any(signal.startswith(ind) for ind in medium_indicators):
            return "medium"

    for signal in signals:
        if signal.startswith("vulnerable_version:"):
            parts = signal.split(":")
            if len(parts) >= 3 and parts[2] in ("critical", "high"):
                return "high"

    return "low"


def _calculate_risk_score(signals: list[str]) -> int:
    score = 0
    severity_scores: dict[str, int] = {
        "debug_mode_enabled": 8,
        "default_configuration_detected": 7,
        "deprecated_api_endpoint": 5,
        "api_v1_endpoint": 4,
        "api_v0_endpoint": 5,
        "legacy_endpoint": 5,
        "explicitly_deprecated_endpoint": 6,
    }

    for signal in signals:
        if signal in severity_scores:
            score += severity_scores[signal]
        elif signal.startswith("vulnerable_version:"):
            parts = signal.split(":")
            if len(parts) >= 3:
                sev = parts[2]
                score += (
                    10 if sev == "critical" else 7 if sev == "high" else 4 if sev == "medium" else 2
                )
        elif signal.startswith("server_version_disclosure:"):
            score += 3
        elif signal.startswith("powered_by_disclosure:"):
            score += 2
        elif signal.startswith("framework_header:"):
            score += 2
        elif signal.startswith("non_production_environment:"):
            score += 5

    return min(score, 20)


def vulnerable_component_detector(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Detect vulnerable component indicators passively.

    Analyzes URLs and responses for:
    - Technology fingerprinting for known vulnerable versions
    - Server header version disclosure
    - X-Powered-By framework version disclosure
    - Outdated library indicators in responses
    - Deprecated API endpoints (v1, v0, old, legacy)
    - Known vulnerable framework patterns
    - Default configuration indicators

    Args:
        urls: Set of URLs to analyze.
        responses: List of HTTP response dicts.
        limit: Maximum number of findings to return.

    Returns:
        List of vulnerable component findings sorted by risk score.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url in sorted(urls):
        if is_noise_url(url):
            continue

        signals = _check_deprecated_endpoints(url)
        if not signals:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(signals)
        risk_score = _calculate_risk_score(signals)
        confidence = normalized_confidence(
            base=0.40,
            score=risk_score,
            signals=signals,
            cap=0.85,
        )

        title_parts: list[str] = []
        if "deprecated_api_endpoint" in signals:
            title_parts.append("Deprecated API Endpoint")
        if "api_v1_endpoint" in signals:
            title_parts.append("API v1 Endpoint")
        if "legacy_endpoint" in signals:
            title_parts.append("Legacy Endpoint")
        if "explicitly_deprecated_endpoint" in signals:
            title_parts.append("Explicitly Deprecated Endpoint")

        title = "; ".join(title_parts) if title_parts else "Deprecated Endpoint Detected"

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
        resp_signals.extend(_check_server_version(response))
        resp_signals.extend(_check_powered_by(response))
        resp_signals.extend(_check_framework_headers(response))
        resp_signals.extend(_check_vulnerable_versions(response))
        resp_signals.extend(_check_default_config(response))

        if not resp_signals:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(resp_signals)
        risk_score = _calculate_risk_score(resp_signals)
        confidence = normalized_confidence(
            base=0.40,
            score=risk_score,
            signals=resp_signals,
            cap=0.92,
        )

        resp_title_parts: list[str] = []
        if any(s.startswith("vulnerable_version:") for s in resp_signals):
            resp_title_parts.append("Known Vulnerable Version Detected")
        if any(s.startswith("server_version_disclosure:") for s in resp_signals):
            resp_title_parts.append("Server Version Disclosure")
        if any(s.startswith("powered_by_disclosure:") for s in resp_signals):
            resp_title_parts.append("Framework Version Disclosure")
        if "debug_mode_enabled" in resp_signals:
            resp_title_parts.append("Debug Mode Enabled")
        if "default_configuration_detected" in resp_signals:
            resp_title_parts.append("Default Configuration Detected")
        if any(s.startswith("non_production_environment:") for s in resp_signals):
            resp_title_parts.append("Non-Production Environment Detected")
        if any(s.startswith("framework_header:") for s in resp_signals):
            resp_title_parts.append("Framework Header Disclosure")

        title = (
            "; ".join(resp_title_parts)
            if resp_title_parts
            else "Vulnerable Component Indicator Detected"
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
