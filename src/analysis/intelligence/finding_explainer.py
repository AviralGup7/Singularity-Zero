"""Finding explainability and executive summary generator."""

from __future__ import annotations

from typing import Any


def generate_finding_explanations(finding: dict[str, Any]) -> dict[str, Any]:
    """Generate persona-tailored explanations for a security finding."""
    title = str(finding.get("title", "Security Finding"))
    severity = str(finding.get("severity", "medium")).lower()
    category = str(finding.get("category", "General Security"))
    url = str(finding.get("url", ""))
    evidence = str(finding.get("evidence") or finding.get("payload") or "")
    _description = str(finding.get("description", ""))

    developer_explanation = (
        f"**Root Cause**: The application component at `{url or 'endpoint'}` fails to adequately validate, "
        f"sanitize, or authorize requests related to {category}.\n\n"
        f"**Impact on Codebase**: An attacker can supply malformed or unauthorized inputs (e.g. `{evidence or 'payload'}`) "
        f"leading to state corruption, unauthorized access, or sensitive data leakage.\n\n"
        f"**Recommended Code Fix**: Implement strict parameter sanitization, enforce parameterized queries/ORM boundaries, "
        f"and verify role-based permissions before processing requests."
    )

    auditor_explanation = (
        f"**Compliance & Control Failure**: This finding maps to a control deficiency in input handling and access control policies.\n\n"
        f"**CVSS Breakdown**: Rated as **{severity.upper()}** due to potential impact on confidentiality and integrity.\n\n"
        f"**Verification Step**: Replay the recorded HTTP request sequence to verify that proper authorization tokens or input filters reject the probe with HTTP 400/403."
    )

    executive_explanation = (
        f"**Business Risk**: A **{severity.upper()}** severity {category} vulnerability was identified in `{url or 'target'}`. "
        f"If exploited, this could compromise customer data, breach compliance standards (SOC 2, ISO 27001), or disrupt service availability. "
        f"Remediation should be prioritized according to SLA targets."
    )

    cat_lower = category.lower()
    if "sql" in cat_lower or "injection" in cat_lower:
        snippet = (
            f"# Parameterized query remediation for {category}\n"
            "def query_database(cursor, user_id, input_param):\n"
            "    # Enforce parameterized query boundaries to prevent SQL injection\n"
            "    cursor.execute('SELECT * FROM records WHERE user_id = %s AND key = %s', (user_id, input_param))\n"
            "    return cursor.fetchall()"
        )
    elif "xss" in cat_lower:
        snippet = (
            f"# Context-aware output encoding for {category}\n"
            "from html import escape\n\n"
            "def render_template(user_input: str) -> str:\n"
            "    # Sanitize and encode user input before reflecting in HTML/DOM context\n"
            "    safe_content = escape(user_input, quote=True)\n"
            "    return f'<div>{safe_content}</div>'"
        )
    elif "ssrf" in cat_lower:
        snippet = (
            f"# Strict egress allowlist enforcement for {category}\n"
            "import ipaddress, urllib.parse\n\n"
            "def fetch_remote_url(target_url: str, allowed_hosts: set[str]):\n"
            "    parsed = urllib.parse.urlparse(target_url)\n"
            "    if parsed.hostname not in allowed_hosts:\n"
            "        raise PermissionError('Target host not in allowed egress boundaries')\n"
            "    # Deny link-local, loopback, and cloud metadata IPs\n"
            "    ip = ipaddress.ip_address(parsed.hostname)\n"
            "    if ip.is_private or ip.is_loopback or str(ip) == '169.254.169.254':\n"
            "        raise PermissionError('Egress to private/metadata IP denied')\n"
            "    return perform_safe_request(target_url)"
        )
    elif "idor" in cat_lower or "auth" in cat_lower or "access" in cat_lower:
        snippet = (
            f"# Authorization check for {category}\n"
            "def access_resource(session_user, resource_id: str):\n"
            "    resource = get_resource_by_id(resource_id)\n"
            "    if resource.tenant_id != session_user.tenant_id or resource.owner_id != session_user.user_id:\n"
            "        raise PermissionError('Unauthorized access to tenant resource')\n"
            "    return resource"
        )
    else:
        snippet = (
            f"# Ensure strict validation and authorization for {category}\n"
            "def secure_handler(request):\n"
            "    validate_input(request.data)\n"
            "    check_permissions(request.user)\n"
            "    return process(request)"
        )

    return {
        "finding_id": finding.get("id"),
        "title": title,
        "severity": severity,
        "personas": {
            "developer": developer_explanation,
            "auditor": auditor_explanation,
            "executive": executive_explanation,
        },
        "remediation_snippet": snippet,
    }


def generate_executive_run_summary(
    findings: list[dict[str, Any]], target: str, run_id: str
) -> dict[str, Any]:
    """Generate executive AI summary across a complete scan run."""
    total = len(findings)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    categories: dict[str, int] = {}

    for f in findings:
        sev = str(f.get("severity", "medium")).lower()
        counts[sev] = counts.get(sev, 0) + 1
        cat = str(f.get("category", "General"))
        categories[cat] = categories.get(cat, 0) + 1

    risk_score = (
        counts.get("critical", 0) * 10
        + counts.get("high", 0) * 5
        + counts.get("medium", 0) * 2
        + counts.get("low", 0)
    )
    posture = (
        "Critical Risk"
        if counts.get("critical", 0) > 0
        else (
            "High Risk"
            if counts.get("high", 0) > 0
            else ("Moderate Risk" if counts.get("medium", 0) > 0 else "Low Risk")
        )
    )

    top_categories = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:3]
    top_categories_str = (
        ", ".join(f"{k} ({v})" for k, v in top_categories) if top_categories else "None"
    )

    overview = (
        f"Automated security assessment for target **{target}** (Run `{run_id}`) discovered **{total}** total findings. "
        f"Overall risk posture is classified as **{posture}** (Risk Index: {risk_score}). "
        f"Most prevalent vulnerability classes: {top_categories_str}."
    )

    recommendations = []
    if counts.get("critical", 0) > 0:
        recommendations.append(
            "Immediate Action: Patch critical remote execution, authentication bypass, or data exposure vulnerabilities within 24 hours."
        )
    if counts.get("high", 0) > 0:
        recommendations.append(
            "High Priority: Address high-severity injection and authorization flaws within 7 days."
        )
    if counts.get("medium", 0) > 0:
        recommendations.append(
            "Scheduled Fix: Resolve medium-severity information disclosure and configuration issues in the next release cycle."
        )
    if not recommendations:
        recommendations.append("Maintain continuous monitoring and periodic regression scanning.")

    return {
        "target": target,
        "run_id": run_id,
        "total_findings": total,
        "severity_breakdown": counts,
        "posture": posture,
        "risk_index": risk_score,
        "overview": overview,
        "recommendations": recommendations,
    }
