"""Map findings categories to compliance framework references.

Supports:
- OWASP Top 10 (2021/2023)
- NIST SP 800-53 controls
- ISO 27001 Annex A controls
- PCI DSS v4.0

Used by the reporting pipeline to generate compliance coverage reports.
"""

from typing import Any

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021)
# ---------------------------------------------------------------------------
OWASP_TOP_10: dict[str, list[str]] = {
    "injection": ["A03:2021-Injection"],
    "sql_injection": ["A03:2021-Injection"],
    "command_injection": ["A03:2021-Injection"],
    "ldap_injection": ["A03:2021-Injection"],
    "xss": ["A03:2021-Injection"],
    "xss_reflected": ["A03:2021-Injection"],
    "xss_stored": ["A03:2021-Injection"],
    "broken_access_control": ["A01:2021-Broken Access Control"],
    "idor": ["A01:2021-Broken Access Control"],
    "lfi": ["A01:2021-Broken Access Control"],
    "rfi": ["A01:2021-Broken Access Control"],
    "path_traversal": ["A01:2021-Broken Access Control"],
    "broken_authentication": ["A07:2021-Identification and Authentication Failures"],
    "brute_force_resistance": ["A07:2021-Identification and Authentication Failures"],
    "session_hijacking": ["A07:2021-Identification and Authentication Failures"],
    "cryptographic_failures": ["A02:2021-Cryptographic Failures"],
    "weak_tls": ["A02:2021-Cryptographic Failures"],
    "ssrf": ["A10:2021-Server-Side Request Forgery"],
    "security_misconfiguration": ["A05:2021-Security Misconfiguration"],
    "open_redirect": ["A05:2021-Security Misconfiguration"],
    "vulnerable_components": ["A06:2021-Vulnerable and Outdated Components"],
    "logging_monitoring": ["A09:2021-Security Logging and Monitoring Failures"],
    "csrf": ["A01:2021-Broken Access Control"],
    "information_disclosure": ["A05:2021-Security Misconfiguration"],
    "race_condition": ["A04:2021-Insecure Design"],
    "method_tampering": ["A05:2021-Security Misconfiguration"],
    "host_header_injection": ["A05:2021-Security Misconfiguration"],
    "cors_misconfiguration": ["A05:2021-Security Misconfiguration"],
}

# ---------------------------------------------------------------------------
# NIST SP 800-53 Rev. 5 Control Mapping
# ---------------------------------------------------------------------------
NIST_CONTROLS: dict[str, list[str]] = {
    "injection": ["SI-10", "SC-5"],
    "sql_injection": ["SI-10", "SC-5", "AC-6"],
    "command_injection": ["SI-2", "SC-5", "AC-6"],
    "xss": ["SI-10", "SI-16"],
    "xss_reflected": ["SI-10", "SI-16"],
    "xss_stored": ["SI-10", "SI-16"],
    "broken_access_control": ["AC-3", "AC-6"],
    "idor": ["AC-3", "AC-6"],
    "lfi": ["AC-6", "SC-4"],
    "rfi": ["AC-6", "SC-7"],
    "path_traversal": ["AC-6", "SC-4"],
    "broken_authentication": ["IA-2", "IA-8"],
    "brute_force_resistance": ["IA-5"],
    "session_hijacking": ["SC-10", "SC-23"],
    "cryptographic_failures": ["SC-8", "SC-13"],
    "weak_tls": ["SC-8", "SC-13"],
    "ssrf": ["SC-7", "AC-4"],
    "security_misconfiguration": ["CM-6", "CM-7"],
    "open_redirect": ["SI-10"],
    "vulnerable_components": ["SI-2"],
    "logging_monitoring": ["AU-2", "AU-3", "AU-6"],
    "csrf": ["SI-16"],
    "information_disclosure": ["AC-3", "SC-3"],
    "race_condition": ["SI-13"],
    "method_tampering": ["CM-6"],
}

# ---------------------------------------------------------------------------
# ISO 27001:2022 Annex A Control Mapping
# ---------------------------------------------------------------------------
ISO_27001_CONTROLS: dict[str, list[str]] = {
    "injection": ["8.30", "8.12"],
    "sql_injection": ["8.30", "8.12"],
    "command_injection": ["8.30", "8.12"],
    "xss": ["8.30", "8.12"],
    "broken_access_control": ["8.2", "8.3"],
    "idor": ["8.2", "8.3"],
    "broken_authentication": ["5.17", "8.6"],
    "cryptographic_failures": ["8.24"],
    "weak_tls": ["8.24"],
    "ssrf": ["8.12", "8.20"],
    "security_misconfiguration": ["8.9", "8.19"],
    "vulnerable_components": ["8.8", "8.19"],
    "logging_monitoring": ["8.15", "8.16"],
    "information_disclosure": ["8.3", "8.12"],
}

# ---------------------------------------------------------------------------
# PCI DSS v4.0 Requirements
# ---------------------------------------------------------------------------
PCI_DSS: dict[str, list[str]] = {
    "sql_injection": ["6.2.4"],
    "command_injection": ["6.2.4"],
    "xss": ["6.2.4"],
    "xss_reflected": ["6.2.4"],
    "xss_stored": ["6.2.4"],
    "injection": ["6.2.4"],
    "broken_access_control": ["7.3", "6.3.1"],
    "idor": ["7.3", "6.3.1"],
    "broken_authentication": ["8.3", "8.6"],
    "brute_force_resistance": ["8.4"],
    "session_hijacking": ["8.2.1"],
    "weak_tls": ["4.2.1"],
    "cryptographic_failures": ["4.2.1"],
    "security_misconfiguration": ["2.2", "6.3"],
    "information_disclosure": ["6.4.1"],
    "logging_monitoring": ["10.2", "10.4"],
}


def map_finding_to_compliance(category: str) -> dict[str, list[str]]:
    """Map a finding category to compliance framework references.

    Args:
        category: Finding category string (e.g., 'sql_injection').

    Returns:
        Dict mapping framework name to list of control references.
    """
    return {
        "OWASP Top 10 (2021)": OWASP_TOP_10.get(category, []),
        "NIST SP 800-53": NIST_CONTROLS.get(category, []),
        "ISO 27001:2022": ISO_27001_CONTROLS.get(category, []),
        "PCI DSS v4.0": PCI_DSS.get(category, []),
    }


def build_compliance_report(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate a compliance coverage report from a list of findings.

    Args:
        findings: Pipeline finding dictionaries.

    Returns:
        Dict with per-framework control coverage and associated findings.
    """
    framework_coverage: dict[str, dict[str, list[str]]] = {}
    category_counts: dict[str, int] = {}

    for finding in findings:
        category = finding.get("category", "unknown")
        title = finding.get("title", "Unknown")
        severity = finding.get("severity", "info")

        category_counts[category] = category_counts.get(category, 0) + 1

        mapped = map_finding_to_compliance(category)
        for framework, controls in mapped.items():
            if framework not in framework_coverage:
                framework_coverage[framework] = {}
            for control in controls:
                if control not in framework_coverage[framework]:
                    framework_coverage[framework][control] = []
                framework_coverage[framework][control].append(f"[{severity}] {title}")

    return {
        "framework_coverage": framework_coverage,
        "category_counts": category_counts,
        "total_findings": len(findings),
    }
