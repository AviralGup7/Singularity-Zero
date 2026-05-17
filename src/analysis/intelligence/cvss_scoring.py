"""CVSS v3.1 scoring for security findings.

Maps pipeline finding categories to CVSS v3.1 vector strings and base scores,
enabling standardized severity assessment and professional report generation.
"""

import math
from dataclasses import dataclass
from typing import Any

from src.core.plugins import register_plugin


@dataclass(frozen=True)
class CVSSScore:
    """CVSS v3.1 score with vector string and breakdown."""

    vector_string: str
    base_score: float
    severity: str  # none, low, medium, high, critical
    attack_vector: str  # N, A, L, P
    attack_complexity: str  # L, H
    privileges_required: str  # N, L, H
    user_interaction: str  # N, R
    scope: str  # U, C
    confidentiality: str  # N, L, H
    integrity: str  # N, L, H
    availability: str  # N, L, H
    explanation: str = ""


# CVSS metric weights for base score calculation
CVSS_WEIGHTS = {
    "attack_vector": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "attack_complexity": {"L": 0.77, "H": 0.44},
    "privileges_required": {"N": 0.85, "L": 0.62, "H": 0.27},
    "user_interaction": {"N": 0.85, "R": 0.62},
    "scope": {"U": 6.42, "C": 7.52},
    "confidentiality": {"N": 0, "L": 0.22, "H": 0.56},
    "integrity": {"N": 0, "L": 0.22, "H": 0.56},
    "availability": {"N": 0, "L": 0.22, "H": 0.56},
}


def _calculate_cvss_base_score(
    av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str
) -> float:
    """Calculate CVSS v3.1 base score from metric values.

    Args:
        av: Attack Vector (N/A/L/P)
        ac: Attack Complexity (L/H)
        pr: Privileges Required (N/L/H)
        ui: User Interaction (N/R)
        s: Scope (U/C)
        c: Confidentiality Impact (N/L/H)
        i: Integrity Impact (N/L/H)
        a: Availability Impact (N/L/H)

    Returns:
        Base score rounded to 1 decimal place (0.0-10.0).
    """
    w = CVSS_WEIGHTS
    iss = 1 - ((1 - w["confidentiality"][c]) * (1 - w["integrity"][i]) * (1 - w["availability"][a]))

    if s == "U":
        impact = w["scope"]["U"] * iss
    else:
        impact = w["scope"]["C"] * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

    exploitability = (
        8.22
        * w["attack_vector"][av]
        * w["attack_complexity"][ac]
        * w["privileges_required"][pr]
        * w["user_interaction"][ui]
    )

    if impact <= 0:
        return 0.0

    if s == "U":
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)

    return round(score, 1)


def _severity_from_score(score: float) -> str:
    """Map CVSS base score to severity label."""
    if score == 0:
        return "none"
    if score <= 3.9:
        return "low"
    if score <= 6.9:
        return "medium"
    if score <= 8.9:
        return "high"
    return "critical"


# Category-to-CVSS mapping with context-aware adjustments
# Each entry defines default CVSS metrics for a finding category
CATEGORY_CVSS_DEFAULTS: dict[str, dict[str, str]] = {
    "idor": {
        "av": "N",
        "ac": "L",
        "pr": "L",
        "ui": "N",
        "s": "U",
        "c": "H",
        "i": "N",
        "a": "N",
        "explanation": "Object-level access control bypass allows unauthorized data access.",
    },
    "ssrf": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "C",
        "c": "H",
        "i": "H",
        "a": "H",
        "explanation": "Server-side request forgery can access internal services and potentially achieve RCE.",
    },
    "open_redirect": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "R",
        "s": "U",
        "c": "L",
        "i": "L",
        "a": "N",
        "explanation": "Open redirect can be used in phishing attacks to redirect users to malicious sites.",
    },
    "token_leak": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "H",
        "i": "N",
        "a": "N",
        "explanation": "Authentication token exposure enables session hijacking.",
    },
    "xss": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "R",
        "s": "C",
        "c": "L",
        "i": "L",
        "a": "N",
        "explanation": "Cross-site scripting allows execution of arbitrary scripts in victim's browser.",
    },
    "access_control": {
        "av": "N",
        "ac": "L",
        "pr": "L",
        "ui": "N",
        "s": "U",
        "c": "H",
        "i": "N",
        "a": "N",
        "explanation": "Broken access control allows unauthorized access to protected resources.",
    },
    "authentication_bypass": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "H",
        "i": "H",
        "a": "N",
        "explanation": "Authentication bypass allows access without valid credentials.",
    },
    "broken_authentication": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "H",
        "i": "N",
        "a": "N",
        "explanation": "Session management weakness allows authentication bypass.",
    },
    "business_logic": {
        "av": "N",
        "ac": "L",
        "pr": "L",
        "ui": "N",
        "s": "U",
        "c": "L",
        "i": "H",
        "a": "L",
        "explanation": "Business logic flaw allows bypassing intended workflow constraints.",
    },
    "misconfiguration": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "L",
        "i": "N",
        "a": "N",
        "explanation": "Security misconfiguration exposes sensitive information or weakens protections.",
    },
    "exposure": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "L",
        "i": "N",
        "a": "N",
        "explanation": "Information exposure reveals sensitive data or internal details.",
    },
    "anomaly": {
        "av": "N",
        "ac": "H",
        "pr": "L",
        "ui": "N",
        "s": "U",
        "c": "L",
        "i": "L",
        "a": "L",
        "explanation": "Anomalous behavior may indicate underlying security weakness.",
    },
    "behavioral_deviation": {
        "av": "N",
        "ac": "L",
        "pr": "L",
        "ui": "N",
        "s": "U",
        "c": "L",
        "i": "L",
        "a": "L",
        "explanation": "Behavioral deviation under mutation suggests inconsistent security controls.",
    },
    "redirect": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "R",
        "s": "U",
        "c": "L",
        "i": "L",
        "a": "N",
        "explanation": "Redirect behavior may enable phishing or trust boundary bypass.",
    },
    "server_side_injection": {
        "av": "N",
        "ac": "L",
        "pr": "L",
        "ui": "N",
        "s": "C",
        "c": "H",
        "i": "H",
        "a": "H",
        "explanation": "Server-side injection vulnerability may allow command execution or data exfiltration.",
    },
    "race_condition": {
        "av": "N",
        "ac": "H",
        "pr": "L",
        "ui": "N",
        "s": "U",
        "c": "L",
        "i": "H",
        "a": "L",
        "explanation": "Race condition allows inconsistent state changes under concurrent requests.",
    },
    "payment": {
        "av": "N",
        "ac": "L",
        "pr": "L",
        "ui": "N",
        "s": "U",
        "c": "L",
        "i": "H",
        "a": "N",
        "explanation": "Payment flow weakness may allow amount manipulation or unauthorized transactions.",
    },
    "sensitive_data": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "H",
        "i": "N",
        "a": "N",
        "explanation": "Sensitive data exposure reveals credentials, PII, or secrets.",
    },
    "cors": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "R",
        "s": "U",
        "c": "L",
        "i": "L",
        "a": "N",
        "explanation": "CORS misconfiguration allows unauthorized cross-origin resource access.",
    },
    "session": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "H",
        "i": "N",
        "a": "N",
        "explanation": "Session management weakness allows session hijacking or fixation.",
    },
    "csrf": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "R",
        "s": "U",
        "c": "N",
        "i": "H",
        "a": "N",
        "explanation": "Cross-site request forgery allows unauthorized state-changing actions on behalf of authenticated users.",
    },
    "ssti": {
        "av": "N",
        "ac": "L",
        "pr": "L",
        "ui": "N",
        "s": "C",
        "c": "H",
        "i": "H",
        "a": "H",
        "explanation": "Server-side template injection may allow arbitrary code execution on the server.",
    },
    "file_upload": {
        "av": "N",
        "ac": "L",
        "pr": "L",
        "ui": "N",
        "s": "U",
        "c": "N",
        "i": "H",
        "a": "H",
        "explanation": "Unrestricted file upload may allow remote code execution or denial of service.",
    },
    "cache_poisoning": {
        "av": "N",
        "ac": "H",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "L",
        "i": "L",
        "a": "L",
        "explanation": "Web cache poisoning may allow serving malicious content to users.",
    },
    "websocket": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "L",
        "i": "L",
        "a": "N",
        "explanation": "WebSocket security weakness may allow unauthorized message injection or data exposure.",
    },
    "oauth": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "R",
        "s": "U",
        "c": "H",
        "i": "N",
        "a": "N",
        "explanation": "OAuth misconfiguration may allow token theft or unauthorized account access.",
    },
    "graphql": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "H",
        "i": "N",
        "a": "L",
        "explanation": "GraphQL misconfiguration may expose schema details or allow resource exhaustion.",
    },
    "dns": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "N",
        "i": "H",
        "a": "N",
        "explanation": "DNS misconfiguration may enable subdomain takeover or email spoofing.",
    },
    "rate_limit": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "N",
        "i": "N",
        "a": "L",
        "explanation": "Missing or bypassable rate limiting may enable brute force or denial of service.",
    },
    "smuggling": {
        "av": "N",
        "ac": "H",
        "pr": "N",
        "ui": "N",
        "s": "C",
        "c": "H",
        "i": "H",
        "a": "H",
        "explanation": "HTTP request smuggling may allow bypassing security controls and accessing internal services.",
    },
    "ldap_injection": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "N",
        "i": "H",
        "a": "N",
        "explanation": "LDAP injection allows unauthorized directory operations and data manipulation.",
    },
    "mass_assignment": {
        "av": "N",
        "ac": "L",
        "pr": "L",
        "ui": "N",
        "s": "U",
        "c": "H",
        "i": "L",
        "a": "N",
        "explanation": "Mass assignment allows modification of internal object properties through crafted input.",
    },
    "cache_deception": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "R",
        "s": "C",
        "c": "H",
        "i": "N",
        "a": "N",
        "explanation": "Web cache deception allows stealing sensitive user data through cached responses.",
    },
    "email_header_injection": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "R",
        "s": "C",
        "c": "L",
        "i": "L",
        "a": "N",
        "explanation": "Email header injection allows modifying email headers to spoof sender or inject content.",
    },
    "xml_bomb": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "N",
        "i": "N",
        "a": "H",
        "explanation": "XML bomb attack causes denial of service through exponential entity expansion.",
    },
    "token_lifetime": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "L",
        "i": "N",
        "a": "N",
        "explanation": "Excessive token lifetime increases window for token theft and replay attacks.",
    },
    "dns_misconfiguration": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "L",
        "i": "N",
        "a": "N",
        "explanation": "DNS misconfiguration may enable subdomain takeover or service disruption.",
    },
    "clickjacking": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "R",
        "s": "U",
        "c": "N",
        "i": "L",
        "a": "N",
        "explanation": "Clickjacking allows tricking users into performing unintended actions.",
    },
    "insecure_deserialization": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "U",
        "c": "H",
        "i": "H",
        "a": "H",
        "explanation": "Insecure deserialization may allow remote code execution on the server.",
    },
    "ssrf_oob": {
        "av": "N",
        "ac": "L",
        "pr": "N",
        "ui": "N",
        "s": "C",
        "c": "H",
        "i": "N",
        "a": "N",
        "explanation": "Out-of-band SSRF allows accessing internal services and exfiltrating data.",
    },
}


def score_finding_cvss(
    category: str,
    *,
    severity: str = "",
    confidence: float = 0.0,
    evidence: dict[str, Any] | None = None,
    auth_required: bool = False,
    user_interaction: bool = False,
    scope_changed: bool = False,
) -> CVSSScore:
    """Calculate CVSS v3.1 score for a security finding.

    Uses category-based defaults with context-aware adjustments based on
    evidence, confidence, and specific finding characteristics.

    Args:
        category: Finding category (idor, ssrf, xss, etc.)
        severity: Finding severity label (high/medium/low/info)
        confidence: Finding confidence score (0.0-1.0)
        evidence: Finding evidence dict for context-aware adjustments
        auth_required: Whether authentication is required to exploit
        user_interaction: Whether user interaction is required
        scope_changed: Whether the vulnerability crosses trust boundaries

    Returns:
        CVSSScore with vector string, base score, severity, and explanation.
    """
    evidence = evidence or {}
    defaults = CATEGORY_CVSS_DEFAULTS.get(
        category,
        {
            "av": "N",
            "ac": "L",
            "pr": "L",
            "ui": "N",
            "s": "U",
            "c": "L",
            "i": "L",
            "a": "N",
            "explanation": f"Security finding in category '{category}' warrants investigation.",
        },
    )

    # Start with defaults
    av = defaults["av"]
    ac = defaults["ac"]
    pr = defaults["pr"]
    ui = defaults["ui"]
    s = defaults["s"]
    c = defaults["c"]
    i = defaults["i"]
    a = defaults["a"]
    explanation = defaults["explanation"]

    # Context-aware adjustments based on evidence

    # If auth is explicitly required, adjust privileges_required
    if auth_required and pr == "N":
        pr = "L"

    # If user interaction is explicitly required
    if user_interaction and ui == "N":
        ui = "R"

    # If scope change is confirmed (e.g., trust boundary shift)
    if scope_changed or evidence.get("trust_boundary_shift"):
        s = "C"

    # High confidence findings with confirmed reproducibility get higher impact
    if confidence >= 0.8 and evidence.get("reproducible"):
        if c == "L":
            c = "H"
        if i == "L":
            i = "H"

    # Validation-confirmed findings get higher confidence in scoring
    validation_state = str(evidence.get("validation_state", ""))
    if validation_state in ("potential_idor", "active_ready", "confirmed"):
        if c == "L":
            c = "H"

    # Multi-signal correlation increases impact assessment
    signals = evidence.get("signals", [])
    if len(signals) >= 3:
        if a == "N":
            a = "L"

    # Auth bypass indicators increase integrity impact
    if (
        evidence.get("auth_bypass_variant")
        or "auth_bypass" in str(evidence.get("combined_signal", "")).lower()
    ):
        i = "H"
        if pr == "L":
            pr = "N"

    # Calculate base score
    base_score = _calculate_cvss_base_score(av, ac, pr, ui, s, c, i, a)
    severity_label = _severity_from_score(base_score)

    # Build vector string
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    return CVSSScore(
        vector_string=vector,
        base_score=base_score,
        severity=severity_label,
        attack_vector=av,
        attack_complexity=ac,
        privileges_required=pr,
        user_interaction=ui,
        scope=s,
        confidentiality=c,
        integrity=i,
        availability=a,
        explanation=explanation,
    )


ENRICHMENT_PROVIDER = "enrichment_provider"


@register_plugin(ENRICHMENT_PROVIDER, "cvss_scoring")
def enrich_findings_with_cvss(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add CVSS scores to a list of findings.

    Args:
        findings: List of finding dicts with category, severity, confidence, evidence.

    Returns:
        List of findings with cvss_score, cvss_vector, and cvss_severity added.
    """
    enriched = []
    for finding in findings:
        category = str(finding.get("category", "")).strip()
        if not category:
            enriched.append(finding)
            continue

        cvss = score_finding_cvss(
            category,
            severity=str(finding.get("severity", "")),
            confidence=float(finding.get("confidence", 0)),
            evidence=finding.get("evidence", {}),
            auth_required=finding.get("endpoint_type", "").upper() == "AUTH",
            user_interaction=bool(finding.get("evidence", {}).get("user_interaction")),
            scope_changed=bool(finding.get("evidence", {}).get("trust_boundary_shift")),
        )

        enriched.append(
            {
                **finding,
                "cvss_score": cvss.base_score,
                "cvss_vector": cvss.vector_string,
                "cvss_severity": cvss.severity,
                "cvss_explanation": cvss.explanation,
            }
        )

    return enriched
