"""Attack chain correlation engine.

Discovers attack chains by correlating individual findings.
Runs automatically after scan completion to identify compound
vulnerability scenarios.

This module provides a class-based approach to correlation that
complements the function-based approach in engine.py.
"""

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class AttackChain:
    """A sequence of vulnerabilities that can be chained together."""

    name: str
    severity: str  # critical, high, medium, low
    steps: list[dict[str, Any]]  # Each step is a finding
    description: str
    impact: str
    cvss_estimate: float = 0.0
    mitre_techniques: list[str] = field(default_factory=list)


class VulnCorrelationEngine:
    """Automatically correlates findings to discover attack chains.

    Rules for correlation:
    1. Information Disclosure + Auth Bypass = Account Takeover
    2. XSS + CSRF = Session Hijacking
    3. Open Redirect + OAuth = Account Takeover
    4. IDOR + Information Disclosure = Data Breach
    5. SSRF + Internal Port Scan = Network Compromise
    6. File Upload + Path Traversal = RCE
    7. SQLi + Information Disclosure = Full Database Access
    8. Weak TLS + Session Fixation = MITM Attack
    """

    # Correlation rules: (finding_type_1, finding_type_2) -> AttackChain
    CORRELATION_RULES: list[dict[str, Any]] = [
        {
            "types": ["information_disclosure", "auth_bypass"],
            "name": "Account Takeover via Information Disclosure",
            "severity": "critical",
            "description": "Information disclosure combined with authentication bypass allows complete account takeover.",
            "impact": "Full account access without credentials",
            "cvss_estimate": 9.1,
            "mitre": ["T1589", "T1078"],
        },
        {
            "types": ["xss", "csrf"],
            "name": "Session Hijacking via XSS+CSRF",
            "severity": "critical",
            "description": "Cross-site scripting combined with CSRF enables session hijacking.",
            "impact": "Attacker can perform actions as authenticated user",
            "cvss_estimate": 8.8,
            "mitre": ["T1189", "T1059"],
        },
        {
            "types": ["open_redirect", "oauth_misconfiguration"],
            "name": "OAuth Account Takeover via Open Redirect",
            "severity": "high",
            "description": "Open redirect combined with OAuth misconfiguration enables account takeover.",
            "impact": "Attacker can steal OAuth tokens",
            "cvss_estimate": 8.1,
            "mitre": ["T1189", "T1550"],
        },
        {
            "types": ["idor", "information_disclosure"],
            "name": "Data Breach via IDOR",
            "severity": "critical",
            "description": "Insecure direct object reference combined with information disclosure enables data breach.",
            "impact": "Unauthorized access to sensitive data",
            "cvss_estimate": 8.6,
            "mitre": ["T1078", "T1530"],
        },
        {
            "types": ["ssrf", "internal_port_scan"],
            "name": "Network Compromise via SSRF",
            "severity": "critical",
            "description": "Server-side request forgery combined with internal port scanning enables network compromise.",
            "impact": "Internal network access and potential lateral movement",
            "cvss_estimate": 9.0,
            "mitre": ["T1189", "T1046"],
        },
        {
            "types": ["file_upload", "path_traversal"],
            "name": "Remote Code Execution via File Upload",
            "severity": "critical",
            "description": "Unrestricted file upload combined with path traversal enables RCE.",
            "impact": "Arbitrary code execution on server",
            "cvss_estimate": 9.8,
            "mitre": ["T1189", "T1059"],
        },
        {
            "types": ["sqli", "information_disclosure"],
            "name": "Full Database Access via SQLi",
            "severity": "critical",
            "description": "SQL injection combined with information disclosure enables full database access.",
            "impact": "Complete database compromise",
            "cvss_estimate": 9.4,
            "mitre": ["T1189", "T1078"],
        },
        {
            "types": ["weak_tls", "session_fixation"],
            "name": "MITM Attack via Weak TLS",
            "severity": "high",
            "description": "Weak TLS configuration combined with session fixation enables MITM attacks.",
            "impact": "Traffic interception and session hijacking",
            "cvss_estimate": 7.5,
            "mitre": ["T1557", "T1078"],
        },
    ]

    def __init__(self) -> None:
        self._chains: list[AttackChain] = []

    def analyze_findings(self, findings: list[dict[str, Any]]) -> list[AttackChain]:
        """Analyze findings for correlated vulnerabilities.

        Args:
            findings: List of finding dicts with 'type', 'url', 'severity' fields

        Returns:
            List of discovered attack chains
        """
        self._chains = []

        # Group findings by type
        findings_by_type: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            ftype = finding.get("type", "").lower()
            if ftype not in findings_by_type:
                findings_by_type[ftype] = []
            findings_by_type[ftype].append(finding)

        # Apply correlation rules
        for rule in self.CORRELATION_RULES:
            type1, type2 = rule["types"]

            if type1 in findings_by_type and type2 in findings_by_type:
                findings1 = findings_by_type[type1]
                findings2 = findings_by_type[type2]

                # Find findings on same domain
                for f1 in findings1:
                    for f2 in findings2:
                        if self._same_domain(f1, f2):
                            chain = AttackChain(
                                name=rule["name"],
                                severity=rule["severity"],
                                steps=[f1, f2],
                                description=rule["description"],
                                impact=rule["impact"],
                                cvss_estimate=rule.get("cvss_estimate", 0.0),
                                mitre_techniques=rule.get("mitre", []),
                            )
                            self._chains.append(chain)

        # Remove duplicate chains (same types on same domain)
        self._chains = self._deduplicate_chains(self._chains)

        return self._chains

    def _same_domain(self, f1: dict[str, Any], f2: dict[str, Any]) -> bool:
        """Check if two findings target the same domain."""
        url1 = str(f1.get("url", "") or f1.get("target", ""))
        url2 = str(f2.get("url", "") or f2.get("target", ""))

        if not url1 or not url2:
            return False

        try:
            domain1 = urlparse(url1).netloc or url1
            domain2 = urlparse(url2).netloc or url2
            return bool(domain1 == domain2)
        except Exception:
            return bool(url1.split("/")[0] == url2.split("/")[0])

    def _deduplicate_chains(self, chains: list[AttackChain]) -> list[AttackChain]:
        """Remove duplicate chains."""
        seen: set[Any] = set()
        unique: list[AttackChain] = []

        for chain in chains:
            key = (chain.name, tuple(s.get("url", "") for s in chain.steps))
            if key not in seen:
                seen.add(key)
                unique.append(chain)

        return unique

    def get_chains_by_severity(self, severity: str) -> list[AttackChain]:
        """Get chains filtered by severity."""
        return [c for c in self._chains if c.severity == severity]

    def get_summary(self) -> dict[str, Any]:
        """Get summary of discovered attack chains."""
        return {
            "total_chains": len(self._chains),
            "critical": len(self.get_chains_by_severity("critical")),
            "high": len(self.get_chains_by_severity("high")),
            "medium": len(self.get_chains_by_severity("medium")),
            "low": len(self.get_chains_by_severity("low")),
            "chains": [
                {
                    "name": c.name,
                    "severity": c.severity,
                    "cvss_estimate": c.cvss_estimate,
                    "steps_count": len(c.steps),
                    "mitre_techniques": c.mitre_techniques,
                }
                for c in self._chains
            ],
        }
