"""Passive detector for OWASP A06: Vulnerable and Outdated Components.

Analyzes HTTP responses for version disclosure, technology fingerprinting,
dependency file exposure, known vulnerable framework signatures, and
debug/development mode indicators.

This package modularizes the vulnerable components detector into separate files
for better maintainability and AI-agent editability.
"""

from typing import Any

from src.analysis.helpers import endpoint_signature, is_noise_url, normalized_confidence

from ._constants import (
    CVE_PATTERNS,
    DEBUG_INDICATORS,
    DEPENDENCY_FILES,
    FRAMEWORK_VERSION_HEADERS,
    KNOWN_VULNERABLE_VERSIONS,
    POWERED_BY_PATTERNS,
    SERVER_VERSION_PATTERNS,
)
from ._helpers import (
    build_finding,
    calculate_risk_score,
    check_cve_patterns,
    check_debug_indicators,
    check_dependency_disclosure,
    check_framework_headers,
    check_vulnerable_versions,
    determine_severity,
    extract_powered_by_technology,
    extract_server_version,
)

__all__ = [
    "vulnerable_component_detector",
    "CVE_PATTERNS",
    "DEBUG_INDICATORS",
    "DEPENDENCY_FILES",
    "FRAMEWORK_VERSION_HEADERS",
    "KNOWN_VULNERABLE_VERSIONS",
    "POWERED_BY_PATTERNS",
    "SERVER_VERSION_PATTERNS",
]


def vulnerable_component_detector(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Detect vulnerable and outdated components in HTTP responses."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for response in responses:
        if len(findings) >= limit:
            break

        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        body = str(response.get("body_text") or "")
        headers_raw = response.get("headers") or {}
        headers = {str(k).lower(): str(v) for k, v in headers_raw.items()}
        status_code = int(response.get("status_code") or 0)

        server_header = headers.get("server", "")
        powered_by_header = headers.get("x-powered-by", "")

        server_issues = extract_server_version(server_header) if server_header else []
        powered_by_issues = (
            extract_powered_by_technology(powered_by_header) if powered_by_header else []
        )
        framework_issues = check_framework_headers(headers)
        vulnerable_versions = check_vulnerable_versions(server_header, powered_by_header, body)
        debug_indicators = check_debug_indicators(body, headers)
        dependency_files = check_dependency_disclosure(url, body, status_code)
        cve_patterns = check_cve_patterns(body)

        all_issues = (
            server_issues
            + powered_by_issues
            + framework_issues
            + vulnerable_versions
            + debug_indicators
            + dependency_files
            + cve_patterns
        )

        if not all_issues:
            continue

        seen.add(endpoint_key)

        risk_score = calculate_risk_score(
            server_issues,
            powered_by_issues,
            framework_issues,
            vulnerable_versions,
            debug_indicators,
            dependency_files,
            cve_patterns,
        )

        has_critical_cve = any(v.get("severity") == "critical" for v in vulnerable_versions) or any(
            c.get("severity") == "critical" for c in cve_patterns
        )
        has_debug = len(debug_indicators) > 0

        severity = determine_severity(risk_score, has_critical_cve, has_debug)

        confidence = normalized_confidence(
            base=0.45,
            score=risk_score,
            signals=[
                "server_version_disclosure" if server_issues else "",
                "powered_by_disclosure" if powered_by_issues else "",
                "framework_header" if framework_issues else "",
                "vulnerable_version" if vulnerable_versions else "",
                "debug_mode" if debug_indicators else "",
                "dependency_disclosure" if dependency_files else "",
                "cve_pattern" if cve_patterns else "",
            ],
        )

        findings.append(
            build_finding(
                url=url,
                severity=severity,
                confidence=confidence,
                risk_score=risk_score,
                server_issues=server_issues,
                powered_by_issues=powered_by_issues,
                framework_issues=framework_issues,
                vulnerable_versions=vulnerable_versions,
                debug_indicators=debug_indicators,
                dependency_files=dependency_files,
                cve_patterns=cve_patterns,
            )
        )

    findings.sort(
        key=lambda item: (-item.get("score", 0), -item.get("confidence", 0), item.get("url", ""))
    )
    return findings[:limit]
