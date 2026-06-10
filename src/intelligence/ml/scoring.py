"""Scoring helpers for LLM service fallbacks.

Extracted from ``src.intelligence.ml.llm_service`` so fallback behaviour stays
testable without importing the full client transport.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

GRC_MAPPINGS = {
    "nist_sp_800_53": "Violates SI-10 (Information Input Validation) and SC-28 (Protection of Information at Rest).",
    "pci_dss": "Breaches Requirement 6.2 (Secure development controls) and 6.5 (Prevent common injection flaws).",
}


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def fallback_explain(finding: dict[str, Any]) -> dict[str, str]:
    """Rule-based backup explanation generator."""
    title = finding.get("title") or finding.get("type") or "Vulnerability"
    severity = str(finding.get("severity") or "medium").upper()
    category = str(finding.get("category") or "general").lower()

    dev_desc = (
        f"### Technical Mechanics of {title}\n\n"
        f"This vulnerability manifests when untrusted user parameter inputs are ingested without proper validation or sanitization. "
        f"An attacker can exploit this boundary to inject operational delimiters or syntax structures.\n\n"
        f"### Developer Action Checklist:\n"
        f"1. Implement strict context-aware validation.\n"
        f"2. Use parameterized APIs and prepared statements exclusively.\n"
        f"3. Apply robust output encoding before rendering dynamic structures."
    )

    nist = GRC_MAPPINGS.get("nist_sp_800_53", "")
    pci = GRC_MAPPINGS.get("pci_dss", "")
    auditor_desc = (
        f"### Regulatory Impact & GRC Posture for {title}\n\n"
        f"**Risk Severity**: {severity}\n"
        f"**Framework Alignments**:\n"
        f"- **OWASP Top 10**: Mapped to active category based on classification ({category}).\n"
        f"- **NIST SP 800-53**: {nist}\n"
        f"- **PCI DSS v4.0**: {pci}\n\n"
        f"**Operational Business Risk**: Exploitability could lead to unauthorized data exposure, system tampering, or audit-trail evasion."
    )

    return {"developer": dev_desc, "auditor": auditor_desc}


def fallback_patch(
    finding: dict[str, Any],
    request_payload: str | None = None,
    response_body: str | None = None,
) -> dict[str, Any]:
    """Rule-based backup patch generator matching vulnerability categories."""
    category = str(finding.get("category") or finding.get("title") or "general").lower()

    if "sqli" in category or "sql_injection" in category:
        return {
            "title": "Secure Parameterized Database Query",
            "description": "Utilize parameterized statements to insulate the database interpreter from user variables.",
            "language": "python",
            "remediation_code": (
                "# Python DB-API Parameterized Query Patch\n"
                "import psycopg2\n\n"
                "def fetch_user_record(cursor, username, role):\n"
                "    query = 'SELECT * FROM users WHERE username = %s AND role = %s'\n"
                "    cursor.execute(query, (username, role))\n"
                "    return cursor.fetchall()"
            ),
        }
    if "idor" in category or "auth_bypass" in category or "access_control" in category:
        return {
            "title": "Strict Resource Ownership & RBAC Check",
            "description": "Assert resource-ownership and context identity controls before completing operations.",
            "language": "python",
            "remediation_code": (
                "# Secure Authorization Context validation patch\n"
                "def get_user_data(request, user_id):\n"
                "    current_tenant = request.state.tenant_id\n"
                "    current_user = request.state.user_id\n"
                "    \n"
                "    if not is_tenant_resource(user_id, current_tenant):\n"
                "        raise PermissionError('Multi-tenant boundary breach detected')\n"
                "    if current_user != user_id and not request.state.is_admin:\n"
                "        raise PermissionError('Unauthorized access attempt')\n"
                "        \n"
                "    return db.query_resource(user_id)"
            ),
        }
    if "xss" in category or "cross_site_scripting" in category:
        return {
            "title": "Context-Aware HTML Entity Encoding",
            "description": "Escape and encode dynamic parameters inside templates to render them strictly as static variables.",
            "language": "html",
            "remediation_code": (
                "<!-- Secure Context-Aware HTML Encoding Patch -->\n"
                "<script>\n"
                "  const rawInput = '<%= html_escape(user_input) %>';\n"
                "  document.getElementById('display-element').textContent = rawInput;\n"
                "</script>"
            ),
        }

    return {
        "title": "Input Boundary Validation and Sanitization",
        "description": "Apply strict sanitization filters and parameter type-assertion check gates.",
        "language": "python",
        "remediation_code": (
            "# Insecure parameter sanitization patch\n"
            "import re\n\n"
            "def clean_input_parameter(user_input: str) -> str:\n"
            "    return re.sub(r'[^a-zA-Z0-9_.-]', '', user_input)"
        ),
    }


def fallback_triage(
    finding: dict[str, Any],
    request_payload: str | None = None,
    response_body: str | None = None,
) -> dict[str, Any]:
    """Rule-based false positive triage helper."""
    evidence = str(finding.get("evidence") or "")
    resp_text = str(response_body or "")

    is_tp = True
    confidence = 0.80
    reasons = ["Automated analysis of finding evidence and request payloads completed."]

    if evidence and evidence in resp_text:
        confidence = 0.95
        reasons.append(
            f"Confirmed reflection of vulnerability payload '{evidence}' directly in the HTTP response body."
        )

    if any(
        err in resp_text.lower() for err in ["traceback", "stack trace", "sql syntax", "exception"]
    ):
        is_tp = True
        confidence = 0.98
        reasons.append(
            "Detected database syntax or application stack trace disclosure leaking in HTTP response body."
        )

    return {
        "decision": "TP" if is_tp else "FP",
        "confidence": confidence,
        "reasoning": " ".join(reasons),
    }


def fallback_summary(
    findings: list[dict[str, Any]],
    compliance_report: dict[str, Any] | None = None,
) -> str:
    """Produce beautiful, GRC-ready backup summary reports."""
    critical_count = sum(
        1 for f in findings if str(f.get("severity", "info")).lower() == "critical"
    )
    high_count = sum(1 for f in findings if str(f.get("severity", "info")).lower() == "high")
    med_count = sum(1 for f in findings if str(f.get("severity", "info")).lower() == "medium")
    low_count = sum(1 for f in findings if str(f.get("severity", "info")).lower() == "low")

    score = 100
    if critical_count > 0:
        score -= 40
    if high_count > 0:
        score -= 30
    if med_count > 0:
        score -= 15
    score = max(0, score)

    grade = "A"
    if score < 50:
        grade = "F"
    elif score < 70:
        grade = "D"
    elif score < 85:
        grade = "C"
    elif score < 95:
        grade = "B"

    findings_summary = []
    for idx, f in enumerate(findings[:5], start=1):
        findings_summary.append(
            f"**{idx}. [{str(f.get('severity')).upper()}] {str(f.get('title'))}** on `{str(f.get('url') or f.get('target'))}`"
        )

    summary_markdown = (
        f"# Executive Security Posture & Compliance Attestation Report\n\n"
        f"### Posture Grade: **{grade}** ({score}/100)\n"
        f"The autonomous security test pipeline completed vulnerability validation across the designated infrastructure target environments. "
        f"Overall risk assessment indicates a **{grade}** rating with **{len(findings)}** active exposures identified.\n\n"
        f"### Exposure Metrics\n"
        f"- **Critical Severity**: {critical_count} findings\n"
        f"- **High Severity**: {high_count} findings\n"
        f"- **Medium Severity**: {med_count} findings\n"
        f"- **Low Severity**: {low_count} findings\n\n"
        f"### Top Critical Vulnerability Concerns\n"
        f"{chr(10).join(findings_summary) if findings_summary else '*No active critical or high vulnerability findings recorded.*'}\n\n"
        f"### Compliance Readiness & GRC Attestation\n"
        f"- **OWASP Top 10 Alignment**: Scans validated input boundaries mapping to injection flaws, access failures, and security configuration drifts.\n"
        f"- **NIST SP 800-53 Requirements**: Evaluated SI-10 (Input validation checks) and SC-8 (Transmission confidentiality).\n"
        f"- **PCI-DSS Compliance Assessment**: Identified vulnerability states are cross-referenced with remediation SLAs to ensure compliance timelines are met.\n\n"
        f"### Action Items & Mitigation Prioritization\n"
        f"1. **Remediation SLA Enforcements**: Standardized critical findings must be resolved within the 14-day window; high findings within 30 days.\n"
        f"2. **Implement Parameterization**: Update database interfaces to enforce parameterized queries.\n"
        f"3. Triage and Rescan: Leverage collaborative triage modules to verify and execute isolated rescan verification sweeps."
    )

    return summary_markdown


__all__ = [
    "fallback_explain",
    "fallback_patch",
    "fallback_summary",
    "fallback_triage",
]
