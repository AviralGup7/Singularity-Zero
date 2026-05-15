"""Risk scoring functions for intelligence-based assessment.

Provides functions for calculating intelligence-enriched risk scores,
scoring endpoint exposure, and computing aggregate risk profiles.
"""

# CVE bonus constants
_CVE_BONUS_PER_CVE = 0.05
_CVE_MAX_BONUS = 0.15
_CVE_CRITICAL_BONUS = 0.1
_CVE_CRITICAL_MAX = 0.3

# MITRE ATT&CK bonus constants
_MITRE_BONUS_PER_TECHNIQUE = 0.03
_MITRE_MAX_BONUS = 0.1
_MITRE_HIGH_IMPACT_BONUS = 0.05
_MITRE_HIGH_IMPACT_MAX = 0.2

# Endpoint intel bonus constants
_ENDPOINT_PAYMENT_BONUS = 0.1
_ENDPOINT_AUTH_PRIVILEGE_BONUS = 0.1

# Exposure score weights for endpoint risk assessment
_EXPOSURE_WEIGHT_MAX_SEVERITY = 0.35
_EXPOSURE_WEIGHT_FINDING_COUNT = 0.20
_EXPOSURE_WEIGHT_TECHNOLOGY = 0.15
_EXPOSURE_WEIGHT_VISIBILITY = 0.15
_EXPOSURE_WEIGHT_AUTH_RISK = 0.15


def calculate_intelligence_risk(
    finding: dict,
    cve_data: list[dict] | None = None,
    mitre_data: list[dict] | None = None,
    endpoint_intel: dict | None = None,
) -> float:
    """Calculate an intelligence-enriched risk score for a finding.

    Combines the base finding severity with threat intelligence context
    to produce a more accurate risk assessment.

    Args:
        finding: Finding dict with severity, confidence, category.
        cve_data: Optional CVE data for this finding.
        mitre_data: Optional MITRE ATT&CK technique data.
        endpoint_intel: Optional endpoint intelligence dict.

    Returns:
        Risk score from 0.0 to 1.0.
    """
    severity_scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}
    base_score = severity_scores.get(finding.get("severity", "low"), 0.3)
    confidence = finding.get("confidence", 0.5)

    # Base risk = severity * confidence
    risk = base_score * confidence

    # CVE bonus: known CVEs increase risk
    if cve_data:
        cve_bonus = min(_CVE_MAX_BONUS, len(cve_data) * _CVE_BONUS_PER_CVE)
        for cve in cve_data:
            if cve.get("cvss_score", 0) >= 9.0:
                cve_bonus = min(_CVE_CRITICAL_MAX, cve_bonus + _CVE_CRITICAL_BONUS)
        risk = min(1.0, risk + cve_bonus)

    # MITRE bonus: mapped techniques increase risk
    if mitre_data:
        mitre_bonus = min(_MITRE_MAX_BONUS, len(mitre_data) * _MITRE_BONUS_PER_TECHNIQUE)
        high_impact = {"initial_access", "execution", "privilege_escalation", "lateral_movement"}
        for tech in mitre_data:
            if tech.get("tactic", "") in high_impact:
                mitre_bonus = min(_MITRE_HIGH_IMPACT_MAX, mitre_bonus + _MITRE_HIGH_IMPACT_BONUS)
        risk = min(1.0, risk + mitre_bonus)

    # Endpoint intel bonus: payment/auth endpoints are higher risk
    if endpoint_intel:
        if endpoint_intel.get("is_payment_endpoint"):
            risk = min(1.0, risk + _ENDPOINT_PAYMENT_BONUS)
        if endpoint_intel.get("auth_required") and endpoint_intel.get("privilege_escalation_risk"):
            risk = min(1.0, risk + _ENDPOINT_AUTH_PRIVILEGE_BONUS)

    return float(round(risk, 3))


def score_endpoint_exposure(
    endpoint: str,
    findings: list[dict],
    tech_stack: list[str] | None = None,
    is_public: bool = True,
) -> dict:
    """Score the exposure risk of a specific endpoint."""
    factors: dict[str, float] = {}
    recommendations: list[str] = []

    severity_scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3, "info": 0.1}
    max_sev = max(
        (severity_scores.get(f.get("severity", "low"), 0.1) for f in findings),
        default=0.0,
    )
    factors["max_finding_severity"] = max_sev
    factors["finding_count"] = min(1.0, len(findings) / 10.0)

    if len(findings) > 5:
        recommendations.append(f"Endpoint has {len(findings)} findings - prioritize remediation")

    risky_techs = {"wordpress", "joomla", "drupal", "struts", "log4j", "spring4shell"}
    if tech_stack:
        tech_lower = {t.lower() for t in tech_stack}
        risky_found = tech_lower & risky_techs
        factors["technology_risk"] = min(1.0, len(risky_found) * 0.3)
        if risky_found:
            recommendations.append(f"Risky technologies detected: {', '.join(risky_found)}")
    else:
        factors["technology_risk"] = 0.0

    factors["visibility"] = 1.0 if is_public else 0.4
    if is_public:
        recommendations.append("Publicly accessible - ensure proper access controls")

    auth_findings = [f for f in findings if "auth" in f.get("category", "").lower()]
    factors["auth_risk"] = min(1.0, len(auth_findings) * 0.3)
    if auth_findings:
        recommendations.append("Authentication-related findings detected - review access controls")

    weights = {
        "max_finding_severity": _EXPOSURE_WEIGHT_MAX_SEVERITY,
        "finding_count": _EXPOSURE_WEIGHT_FINDING_COUNT,
        "technology_risk": _EXPOSURE_WEIGHT_TECHNOLOGY,
        "visibility": _EXPOSURE_WEIGHT_VISIBILITY,
        "auth_risk": _EXPOSURE_WEIGHT_AUTH_RISK,
    }
    exposure_score = sum(factors.get(k, 0) * v for k, v in weights.items())

    risk_level = (
        "critical"
        if exposure_score >= 0.8
        else "high"
        if exposure_score >= 0.6
        else "medium"
        if exposure_score >= 0.4
        else "low"
    )

    return {
        "endpoint": endpoint,
        "exposure_score": round(exposure_score, 3),
        "risk_level": risk_level,
        "factors": factors,
        "recommendations": recommendations,
    }


def aggregate_risk_profile(
    findings: list[dict],
    endpoints: list[dict] | None = None,
    tech_summary: dict | None = None,
) -> dict:
    """Compute an aggregate risk profile across all findings and endpoints."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    category_counts: dict[str, int] = {}

    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        cat = f.get("category", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
    weighted_sum = sum(severity_counts[k] * severity_weights[k] for k in severity_counts)
    total_findings = sum(severity_counts.values()) or 1
    overall_risk = min(1.0, weighted_sum / (total_findings * 10))

    top_risky_endpoints = []
    if endpoints:
        ep_scores = []
        for ep in endpoints:
            ep_findings = [f for f in findings if f.get("url", "").startswith(ep.get("url", ""))]
            if ep_findings:
                score = score_endpoint_exposure(
                    ep.get("url", ""),
                    ep_findings,
                    ep.get("tech_stack"),
                    ep.get("is_public", True),
                )
                ep_scores.append(score)
        ep_scores.sort(key=lambda x: x["exposure_score"], reverse=True)
        top_risky_endpoints = ep_scores[:10]

    technology_risks = []
    if tech_summary:
        for tech, details in tech_summary.items():
            if isinstance(details, dict) and details.get("version"):
                version = details["version"]
                if any(v in version.lower() for v in ("old", "deprecated", "eol")):
                    technology_risks.append(
                        {
                            "technology": tech,
                            "version": version,
                            "risk": "deprecated",
                        }
                    )

    risk_level = (
        "critical"
        if overall_risk >= 0.8
        else "high"
        if overall_risk >= 0.6
        else "medium"
        if overall_risk >= 0.4
        else "low"
    )

    return {
        "overall_risk_score": round(overall_risk, 3),
        "overall_risk_level": risk_level,
        "severity_breakdown": severity_counts,
        "category_breakdown": category_counts,
        "total_findings": total_findings,
        "top_risky_endpoints": top_risky_endpoints,
        "technology_risks": technology_risks,
    }
