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
    (
        r"Django/3\.[01]\.",
        "Django 3.0-3.1",
        "medium",
        "Outdated Django with known security patches needed",
    ),
    (r"Django/3\.\d+\.", "Django 3.x", "low", "Older Django branch; verify latest patch level"),
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

_FRONTEND_LIBRARY_PATTERNS = [
    (r"(?i)jquery[/-]?([0-2]\.\d+\.\d+)", "jQuery < 3.x", "medium"),
    (r"(?i)react(?:-dom)?[/-]?([0-1]?[0-5]\.\d+\.\d+)", "React < 16.x", "low"),
    (r"(?i)angular(?:\.min)?\.js.*\b[vV]?([1]\.\d+\.\d+)", "AngularJS 1.x", "high"),
    (r"(?i)vue[/-]?([1-2]\.\d+\.\d+)", "Vue.js < 3.x", "medium"),
    (r"(?i)moment[/-]?([1-2]\.[0-1][0-9]\.\d+)", "Moment.js < 2.29", "low"),
    (r"(?i)lodash[/-]?([1-3]\.\d+\.\d+|4\.[0-1][0-6]\.\d+)", "Lodash < 4.17", "medium"),
]


def _check_frontend_dependencies(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Check for outdated or vulnerable frontend dependencies in the response body."""
    issues: list[dict[str, Any]] = []
    body = str(response.get("body_text") or "")

    # Quick filter to avoid heavy regex on non-HTML/JS
    content_type = str(response.get("headers", {}).get("content-type", "")).lower()
    if not ("html" in content_type or "javascript" in content_type or "json" in content_type):
        return issues

    for pattern, lib_desc, severity in _FRONTEND_LIBRARY_PATTERNS:
        match = re.search(pattern, body)
        if match:
            issues.append(
                {
                    "library": lib_desc,
                    "version": match.group(1) if match.lastindex else "",
                    "severity": severity,
                }
            )

    return issues


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

_DEBUG_BODY_PATTERNS = re.compile(
    r"(?:debug:\s*true|Traceback\s+\(most\s+recent\s+call\s+last\)|"
    r"SQL\s+syntax\s+error\s+near|Flask\s+Debugger\s+enabled)",
    re.IGNORECASE,
)

_FRAMEWORK_VERSION_HEADERS: dict[str, tuple[str, str]] = {
    "x-aspnet-version": ("ASP.NET", "Microsoft framework version disclosure"),
    "x-aspnetmvc-version": ("ASP.NET MVC", "Microsoft MVC framework version disclosure"),
    "x-runtime": ("Ruby on Rails", "Ruby/Rails runtime disclosure"),
    "x-rack-version": ("Rack", "Ruby middleware version disclosure"),
    "x-generator": ("CMS/Generator", "Content management system disclosure"),
    "x-envoy-upstream-service-time": ("Envoy", "Service mesh disclosure"),
}


def _check_server_version(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Check Server header for version disclosure."""
    issues: list[dict[str, Any]] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    server_header = headers.get("server", "")

    if not server_header:
        return issues

    for pattern, tech, _desc in _SERVER_VERSION_PATTERNS:
        match = re.search(pattern, server_header)
        if match:
            version = match.group(1) if match.lastindex else ""
            issues.append(
                {
                    "technology": tech,
                    "version": version,
                    "raw": server_header,
                }
            )
            break

    return issues


def _check_powered_by(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Check X-Powered-By header for framework version disclosure."""
    issues: list[dict[str, Any]] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    powered_by = headers.get("x-powered-by", "")

    if not powered_by:
        return issues

    for pattern, tech, _desc in _POWERED_BY_PATTERNS:
        match = re.search(pattern, powered_by)
        if match:
            version = match.group(1) if match.lastindex else ""
            issues.append(
                {
                    "technology": tech,
                    "version": version,
                    "raw": powered_by,
                }
            )
            break

    return issues


def _check_framework_headers(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Check for framework-specific version headers."""
    issues: list[dict[str, Any]] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}

    for header_name, (tech, _desc) in _FRAMEWORK_VERSION_HEADERS.items():
        if header_name in headers:
            value = headers[header_name]
            issues.append(
                {
                    "technology": tech,
                    "header": header_name,
                    "value": value[:50],
                }
            )

    return issues


def _check_vulnerable_versions(
    response: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Check for known vulnerable version patterns.

    Returns (server/powered_by matches, frontend matches) so the caller
    can attach each to its corresponding evidence bucket.
    """
    server_matches: list[dict[str, Any]] = []
    frontend_matches: list[dict[str, Any]] = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    body = str(response.get("body_text") or "")

    server_header = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    combined = f"{server_header} {powered_by} {body[:5000]}"

    for pattern, component, severity, desc in _KNOWN_VULNERABLE_VERSIONS:
        match = re.search(pattern, combined)
        if match:
            entry = {
                "component": component,
                "severity": severity,
                "description": desc,
            }
            if component.endswith(".x") and any(
                keyword in component.lower()
                for keyword in ("jquery", "react", "vue", "moment", "lodash")
            ):
                frontend_matches.append(entry)
            else:
                server_matches.append(entry)

    return server_matches, frontend_matches


def _check_debug_indicators(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Check for debug/development mode indicators in headers and body."""
    indicators: list[dict[str, Any]] = []
    body = str(response.get("body_text") or "")
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}

    # Body-level debug indicators (specific phrases)
    if _DEBUG_BODY_PATTERNS.search(body):
        # Try to identify the specific indicator
        for pattern_str, label in (
            (r"debug:\s*true", "Debug flag in body"),
            (r"Traceback\s+\(most\s+recent\s+call\s+last\)", "Stack trace exposure"),
            (r"SQL\s+syntax\s+error\s+near", "SQL error exposure"),
            (r"Flask\s+Debugger\s+enabled", "Flask debugger"),
        ):
            match_body = re.search(pattern_str, body, re.IGNORECASE)
            if match_body:
                indicators.append(
                    {
                        "indicator": label,
                        "value": match_body.group(0)[:100],
                    }
                )
                break

    # Header-level debug indicators
    if headers.get("x-debug", "").lower() in ("true", "1", "yes", "on"):
        indicators.append(
            {
                "indicator": "X-Debug-Token header"
                if "x-debug-token" in headers
                else "X-Debug header",
                "value": headers.get("x-debug-token") or headers.get("x-debug", ""),
            }
        )
    elif "x-debug-token" in headers:
        indicators.append(
            {
                "indicator": "X-Debug-Token header",
                "value": headers["x-debug-token"],
            }
        )

    if "x-environment" in headers:
        env_val = headers["x-environment"].lower()
        if env_val in ("development", "dev", "debug", "staging", "test"):
            indicators.append(
                {
                    "indicator": f"Non-production environment: {env_val}",
                    "value": env_val,
                }
            )

    return indicators


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


def _calculate_severity(evidence: dict[str, list[dict[str, Any]]]) -> str:
    if evidence.get("debug_indicators"):
        return "critical"
    if evidence.get("vulnerable_versions"):
        severities = {v["severity"] for v in evidence["vulnerable_versions"]}
        if "critical" in severities:
            return "critical"
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
    if evidence.get("default_configuration") or evidence.get("framework_issues"):
        return "high"
    if evidence.get("server_issues") or evidence.get("powered_by_issues"):
        return "medium"
    if evidence.get("frontend_issues"):
        return "medium"
    return "low"


def _calculate_risk_score(evidence: dict[str, list[dict[str, Any]]]) -> int:
    score = 0
    score += 3 * len(evidence.get("server_issues", []))
    score += 2 * len(evidence.get("powered_by_issues", []))
    score += 2 * len(evidence.get("framework_issues", []))
    score += 5 * len(evidence.get("debug_indicators", []))
    for v in evidence.get("vulnerable_versions", []):
        sev = v.get("severity", "low")
        score += 10 if sev == "critical" else 7 if sev == "high" else 4 if sev == "medium" else 2
    for f in evidence.get("frontend_issues", []):
        sev = f.get("severity", "low")
        score += 5 if sev == "critical" else 4 if sev == "high" else 3 if sev == "medium" else 1
    return min(score, 20)


def _signals_from_evidence(evidence: dict[str, list[dict[str, Any]]]) -> list[str]:
    signals: list[str] = []
    if evidence.get("server_issues"):
        signals.append("server_version_disclosure")
    if evidence.get("powered_by_issues"):
        signals.append("powered_by_disclosure")
    if evidence.get("framework_issues"):
        signals.append("framework_header")
    if evidence.get("vulnerable_versions"):
        signals.append("vulnerable_version")
    if evidence.get("debug_indicators"):
        signals.append("debug_mode")
    if evidence.get("frontend_issues"):
        signals.append("vulnerable_version")
    return sorted(set(signals))


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
        evidence: dict[str, list[dict[str, Any]]] = {
            "deprecated_endpoints": [{"indicators": signals}]
        }
        severity = "medium"
        risk_score = 5
        confidence = normalized_confidence(base=0.40, score=risk_score, signals=signals, cap=0.85)
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": signals,
                "evidence": evidence,
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": "Deprecated API endpoint pattern detected",
            }
        )

    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        server_issues = _check_server_version(response)
        powered_by_issues = _check_powered_by(response)
        framework_issues = _check_framework_headers(response)
        server_vuln, frontend_vuln = _check_vulnerable_versions(response)
        debug_indicators = _check_debug_indicators(response)
        frontend_issues = _check_frontend_dependencies(response)

        # Merge vulnerability buckets
        vulnerable_versions = list(server_vuln)
        # Frontend library vulnerability findings appear in their own bucket
        # but should also count as a "vulnerable_version" signal.

        evidence = {}
        if server_issues:
            evidence["server_issues"] = server_issues
        if powered_by_issues:
            evidence["powered_by_issues"] = powered_by_issues
        if framework_issues:
            evidence["framework_issues"] = framework_issues
        if vulnerable_versions:
            evidence["vulnerable_versions"] = vulnerable_versions
        if debug_indicators:
            evidence["debug_indicators"] = debug_indicators
        if frontend_issues:
            evidence["frontend_issues"] = frontend_issues
        if frontend_vuln:
            # Promote frontend vulnerability list to its own bucket too
            evidence["vulnerable_versions"] = (
                evidence.get("vulnerable_versions", []) + frontend_vuln
            )

        if not evidence:
            continue

        seen.add(endpoint_key)
        signals = _signals_from_evidence(evidence)
        severity = _calculate_severity(evidence)
        risk_score = _calculate_risk_score(evidence)
        confidence = normalized_confidence(
            base=0.40,
            score=risk_score,
            signals=signals,
            cap=0.92,
        )

        title_parts: list[str] = []
        if any(s == "vulnerable_version" for s in signals):
            if evidence.get("frontend_issues"):
                title_parts.append("Outdated/Vulnerable Frontend Library")
            else:
                title_parts.append("Known Vulnerable Version Detected")
        if "server_version_disclosure" in signals:
            title_parts.append("Server Version Disclosure")
        if "powered_by_disclosure" in signals:
            title_parts.append("Framework Version Disclosure")
        if "debug_mode" in signals:
            title_parts.append("Debug Mode Enabled")
        if "framework_header" in signals:
            title_parts.append("Framework Header Disclosure")

        title = "; ".join(title_parts) if title_parts else "Vulnerable Component Indicator Detected"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": signals,
                "evidence": evidence,
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    findings.sort(key=lambda item: (-item["risk_score"], item["url"]))
    return findings[:limit]
