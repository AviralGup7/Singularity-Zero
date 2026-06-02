"""Helper functions for vulnerable components detection."""

import re
from typing import Any

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
)

from ._constants import (
    CVE_PATTERNS,
    DEBUG_INDICATORS,
    DEPENDENCY_FILES,
    FRAMEWORK_VERSION_HEADERS,
    KNOWN_VULNERABLE_VERSIONS,
    POWERED_BY_PATTERNS,
    SERVER_VERSION_PATTERNS,
)


def extract_server_version(server_header: str) -> list[dict[str, str]]:
    """Extract server version information from Server header."""
    results: list[dict[str, str]] = []
    for pattern, tech, desc in SERVER_VERSION_PATTERNS:
        match = re.search(pattern, server_header)
        if match:
            version = match.group(1) if match.lastindex else ""
            results.append(
                {
                    "technology": tech,
                    "version": version,
                    "description": desc,
                    "evidence": server_header,
                }
            )
    return results


def extract_powered_by_technology(header_value: str) -> list[dict[str, str]]:
    """Extract technology information from X-Powered-By header."""
    results: list[dict[str, str]] = []
    for pattern, tech, desc in POWERED_BY_PATTERNS:
        match = re.search(pattern, header_value)
        if match:
            version = match.group(1) if match.lastindex else ""
            results.append(
                {
                    "technology": tech,
                    "version": version,
                    "description": desc,
                    "evidence": header_value,
                }
            )
    return results


def check_framework_headers(headers: dict[str, str]) -> list[dict[str, str]]:
    """Check for framework-specific version headers."""
    results: list[dict[str, str]] = []
    for header_name, (tech, desc) in FRAMEWORK_VERSION_HEADERS.items():
        if header_name in headers:
            value = headers[header_name]
            results.append(
                {
                    "technology": tech,
                    "version": value,
                    "description": desc,
                    "evidence": f"{header_name}: {value}",
                }
            )
    return results


def check_vulnerable_versions(
    server_header: str, powered_by: str, body: str
) -> list[dict[str, str]]:
    """Check for known vulnerable version patterns."""
    results: list[dict[str, str]] = []
    combined = f"{server_header} {powered_by} {body[:5000]}"
    for pattern, component, severity, desc in KNOWN_VULNERABLE_VERSIONS:
        match = re.search(pattern, combined)
        if match:
            results.append(
                {
                    "component": component,
                    "severity": severity,
                    "description": desc,
                    "evidence": match.group(0),
                }
            )
    return results


def check_debug_indicators(body: str, headers: dict[str, str]) -> list[dict[str, str]]:
    """Check for debug/development mode indicators."""
    results: list[dict[str, str]] = []
    for pattern, desc, severity in DEBUG_INDICATORS:
        match = re.search(pattern, body[:5000])
        if match:
            results.append(
                {
                    "indicator": desc,
                    "severity": severity,
                    "evidence": match.group(0)[:200],
                }
            )
    if "x-debug" in headers or "x-debug-token" in headers:
        results.append(
            {
                "indicator": "Debug header present",
                "severity": "high",
                "evidence": f"x-debug: {headers.get('x-debug', '')}"
                if "x-debug" in headers
                else f"x-debug-token: {headers.get('x-debug-token', '')}",
            }
        )
    if "x-environment" in headers:
        env_val = headers["x-environment"].lower()
        if env_val in ("development", "dev", "debug", "staging"):
            results.append(
                {
                    "indicator": f"Environment header reveals {env_val} mode",
                    "severity": "high",
                    "evidence": f"x-environment: {headers['x-environment']}",
                }
            )
    return results


def check_dependency_disclosure(url: str, body: str, status_code: int) -> list[dict[str, str]]:
    """Check if response reveals dependency files."""
    results: list[dict[str, str]] = []
    for path, name, desc in DEPENDENCY_FILES:
        if url.rstrip("/").endswith(path) or url.rstrip("/").endswith("/" + path.lstrip("/")):
            if 200 <= status_code < 300 and len(body) > 10:
                results.append(
                    {
                        "file": name,
                        "description": desc,
                        "evidence": f"URL: {url}, Status: {status_code}",
                    }
                )
            break
    return results


def check_cve_patterns(body: str) -> list[dict[str, str]]:
    """Check for known CVE and vulnerability patterns in response body."""
    results: list[dict[str, str]] = []
    for pattern, desc, severity, detail in CVE_PATTERNS:
        match = re.search(pattern, body[:5000])
        if match:
            results.append(
                {
                    "pattern": desc,
                    "severity": severity,
                    "description": detail,
                    "evidence": match.group(0)[:200],
                }
            )
    return results


def calculate_risk_score(
    server_issues: list[dict[str, str]],
    powered_by_issues: list[dict[str, str]],
    framework_issues: list[dict[str, str]],
    vulnerable_versions: list[dict[str, str]],
    debug_indicators: list[dict[str, str]],
    dependency_files: list[dict[str, str]],
    cve_patterns: list[dict[str, str]],
) -> int:
    """Calculate overall risk score from all findings."""
    score = 0
    score += len(server_issues) * 2
    score += len(powered_by_issues) * 2
    score += len(framework_issues) * 1
    for vuln in vulnerable_versions:
        sev = vuln.get("severity", "low")
        score += 10 if sev == "critical" else 7 if sev == "high" else 4 if sev == "medium" else 2
    for debug in debug_indicators:
        sev = debug.get("severity", "low")
        score += 8 if sev == "critical" else 5 if sev == "high" else 3 if sev == "medium" else 1
    score += len(dependency_files) * 4
    for cve in cve_patterns:
        sev = cve.get("severity", "low")
        score += 8 if sev == "critical" else 5 if sev == "high" else 3 if sev == "medium" else 1
    return score


def determine_severity(risk_score: int, has_critical_cve: bool, has_debug: bool) -> str:
    """Determine overall severity from risk score and flags."""
    if has_critical_cve or risk_score >= 20:
        return "critical"
    if risk_score >= 12:
        return "high"
    if risk_score >= 6 or has_debug:
        return "medium"
    return "low"


def build_finding(
    url: str,
    severity: str,
    confidence: float,
    risk_score: int,
    server_issues: list[dict[str, str]],
    powered_by_issues: list[dict[str, str]],
    framework_issues: list[dict[str, str]],
    vulnerable_versions: list[dict[str, str]],
    debug_indicators: list[dict[str, str]],
    dependency_files: list[dict[str, str]],
    cve_patterns: list[dict[str, str]],
) -> dict[str, Any]:
    """Build a standardized finding dict."""
    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        "category": "vulnerable_components",
        "title": f"Vulnerable and outdated components detected: {url}",
        "severity": severity,
        "confidence": round(confidence, 2),
        "score": risk_score,
        "signals": sorted(
            {
                "server_version_disclosure" if server_issues else "",
                "powered_by_disclosure" if powered_by_issues else "",
                "framework_header" if framework_issues else "",
                "vulnerable_version" if vulnerable_versions else "",
                "debug_mode" if debug_indicators else "",
                "dependency_disclosure" if dependency_files else "",
                "cve_pattern" if cve_patterns else "",
            }
            - {""}
        ),
        "evidence": {
            "server_issues": server_issues,
            "powered_by_issues": powered_by_issues,
            "framework_issues": framework_issues,
            "vulnerable_versions": vulnerable_versions,
            "debug_indicators": debug_indicators,
            "dependency_files": dependency_files,
            "cve_patterns": cve_patterns,
            "risk_score": risk_score,
        },
        "explanation": (
            f"Endpoint '{url}' reveals technology stack information including "
            f"{len(server_issues)} server version disclosures, "
            f"{len(powered_by_issues)} X-Powered-By disclosures, "
            f"{len(vulnerable_versions)} potentially vulnerable versions, "
            f"and {len(debug_indicators)} debug indicators. "
            f"Risk score: {risk_score}."
        ),
    }
