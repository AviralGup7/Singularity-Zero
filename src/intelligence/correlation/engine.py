"""Cross-finding correlation engine for detecting attack chains and compound risk.

Analyzes findings across modules to identify:
- Multi-vector endpoints (same endpoint flagged by multiple independent detectors)
- Attack chains (e.g., SSRF + IDOR on same resource = critical)
- Compound risk scoring (combined severity when multiple vulnerabilities coexist)
- Temporal correlation (findings that persist or evolve across runs)
"""

from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

# Attack chain patterns: combinations of categories that indicate higher risk
ATTACK_CHAINS: dict[str, tuple[tuple[str, ...], str, float]] = {
    # SSRF + IDOR = internal resource access via SSRF
    "ssrf_idor_chain": (
        ("ssrf", "idor"),
        "SSRF-enabled IDOR: internal resource access via server-side request",
        0.20,
    ),
    # Auth bypass + access control = privilege escalation path
    "auth_bypass_access_control": (
        ("authentication_bypass", "access_control"),
        "Auth bypass with access control weakness: privilege escalation path",
        0.18,
    ),
    # XSS + token leak = session hijacking
    "xss_token_hijack": (
        ("xss", "token_leak"),
        "XSS with token exposure: session hijacking vector",
        0.18,
    ),
    # SSRF + auth bypass = internal service access
    "ssrf_auth_bypass": (
        ("ssrf", "authentication_bypass"),
        "SSRF with auth bypass: internal service access without authentication",
        0.22,
    ),
    # IDOR + sensitive data = data breach
    "idor_sensitive_data": (
        ("idor", "sensitive_data"),
        "IDOR with sensitive data exposure: cross-user data breach risk",
        0.16,
    ),
    # Business logic + payment = financial impact
    "business_logic_payment": (
        ("business_logic", "payment"),
        "Business logic flaw in payment flow: financial manipulation risk",
        0.20,
    ),
    # Open redirect + token leak = OAuth token theft
    "redirect_token_theft": (
        ("open_redirect", "token_leak"),
        "Open redirect with token leak: OAuth token theft via redirect manipulation",
        0.16,
    ),
    # SSRF + sensitive data = internal data exfiltration
    "ssrf_sensitive_data": (
        ("ssrf", "sensitive_data"),
        "SSRF with sensitive data: internal data exfiltration via server-side request",
        0.18,
    ),
    # CORS + auth bypass = cross-origin auth bypass
    "cors_auth_bypass": (
        ("cors", "authentication_bypass"),
        "CORS misconfiguration with auth bypass: cross-origin authentication bypass",
        0.16,
    ),
    # Race condition + payment = financial race condition
    "race_payment": (
        ("race_condition", "payment"),
        "Race condition in payment flow: double-spend or coupon abuse risk",
        0.18,
    ),
    # Token leak + broken authentication = session fixation
    "token_broken_auth": (
        ("token_leak", "broken_authentication"),
        "Token exposure with session management weakness: session fixation risk",
        0.16,
    ),
    # IDOR + business logic = workflow manipulation
    "idor_business_logic": (
        ("idor", "business_logic"),
        "IDOR with business logic flaw: workflow manipulation via object reference",
        0.14,
    ),
    # Server-side injection + SSRF = RCE path
    "injection_ssrf": (
        ("server_side_injection", "ssrf"),
        "Server-side injection with SSRF: potential remote code execution path",
        0.25,
    ),
    # XSS + business logic = stored XSS in workflow
    "xss_business_logic": (
        ("xss", "business_logic"),
        "XSS with business logic flaw: stored XSS in multi-step workflow",
        0.16,
    ),
    # Session + access control = session-based access bypass
    "session_access_control": (
        ("session", "access_control"),
        "Session weakness with access control gap: session-based access bypass",
        0.18,
    ),
    # Misconfiguration + exposure = information disclosure chain
    "misconfig_exposure": (
        ("misconfiguration", "exposure"),
        "Misconfiguration with information exposure: compounded information disclosure",
        0.10,
    ),
    # Auth bypass + session = complete auth bypass
    "auth_bypass_session": (
        ("authentication_bypass", "broken_authentication"),
        "Authentication bypass with session weakness: complete authentication bypass",
        0.22,
    ),
    # Three-vector chains (highest risk)
    "ssrf_idor_sensitive": (
        ("ssrf", "idor", "sensitive_data"),
        "Critical: SSRF + IDOR + sensitive data = internal data breach via server-side request",
        0.30,
    ),
    "auth_bypass_idor_sensitive": (
        ("authentication_bypass", "idor", "sensitive_data"),
        "Critical: Auth bypass + IDOR + sensitive data = unauthorized data access at scale",
        0.28,
    ),
    "xss_token_auth_bypass": (
        ("xss", "token_leak", "authentication_bypass"),
        "Critical: XSS + token leak + auth bypass = complete account takeover",
        0.30,
    ),
}

# Severity escalation thresholds
SEVERITY_ESCALATION = {
    "low": {"min_chain_count": 2, "escalated_to": "medium"},
    "medium": {"min_chain_count": 2, "escalated_to": "high"},
    "high": {"min_chain_count": 1, "escalated_to": "critical"},
}


def correlate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Analyze findings for cross-module correlations and attack chains.

    Groups findings by endpoint and identifies:
    - Multi-vector endpoints (multiple independent detections)
    - Attack chain patterns (dangerous category combinations)
    - Compound risk scores (combined severity)

    Args:
        findings: List of finding dicts from merge_findings().

    Returns:
        Findings list with added correlation metadata:
        - correlation_bonus: confidence boost from correlation
        - attack_chains: list of detected attack chain names
        - compound_risk_score: combined risk score
        - multi_vector: whether endpoint has multiple independent findings
    """
    # Group findings by endpoint base key
    endpoint_findings: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        evidence = finding.get("evidence", {}) or {}
        endpoint_key = str(
            evidence.get("endpoint_base_key")
            or evidence.get("endpoint_key")
            or finding.get("url", "")
        )
        endpoint_findings[endpoint_key].append(finding)

    # Apply correlation to each endpoint group
    for endpoint_key, group in endpoint_findings.items():
        if len(group) < 2:
            # Single finding: mark as not multi-vector
            for finding in group:
                finding["multi_vector"] = False
                finding["attack_chains"] = []
                finding["correlation_bonus"] = 0.0
                finding["compound_risk_score"] = finding.get("score", 0)
            continue

        # Multi-vector endpoint: compute correlation
        categories = {str(f.get("category", "")).strip() for f in group}
        modules = {str(f.get("module", "")).strip() for f in group}
        non_empty_categories = {value for value in categories if value}
        non_empty_modules = {value for value in modules if value}

        # Multiple records from the same module/category are duplicates, not independent vectors.
        if len(non_empty_categories) < 2 and len(non_empty_modules) < 2:
            for finding in group:
                finding["multi_vector"] = False
                finding["attack_chains"] = []
                finding["correlation_bonus"] = 0.0
                finding["compound_risk_score"] = finding.get("score", 0)
                finding["correlated_module_count"] = len(non_empty_modules)
            continue

        # Detect attack chains
        detected_chains: list[str] = []
        total_chain_bonus = 0.0
        for chain_name, (required_categories, description, bonus) in ATTACK_CHAINS.items():
            if all(cat in non_empty_categories for cat in required_categories):
                detected_chains.append(chain_name)
                total_chain_bonus += bonus

        # Correlation bonus: scales with number of independent modules
        module_count = max(len(non_empty_modules), 1)
        module_bonus = min((module_count - 1) * 0.05, 0.15)
        total_bonus = min(total_chain_bonus + module_bonus, 0.30)

        # Compound risk score: base score + correlation bonus
        max_base_score = max(f.get("score", 0) for f in group)
        compound_score = max_base_score + int(total_bonus * 20)

        # Apply to all findings in the group
        for finding in group:
            finding["multi_vector"] = True
            finding["attack_chains"] = detected_chains
            finding["correlation_bonus"] = round(total_bonus, 2)
            finding["compound_risk_score"] = compound_score
            finding["correlated_module_count"] = module_count

            # Boost confidence based on correlation
            original_confidence = float(finding.get("confidence", 0))
            boosted_confidence = min(original_confidence + total_bonus, 0.98)
            finding["confidence"] = round(boosted_confidence, 2)

            # Add chain descriptions to explanation
            if detected_chains:
                chain_descriptions = [
                    ATTACK_CHAINS[chain][1] for chain in detected_chains if chain in ATTACK_CHAINS
                ]
                existing_explanation = finding.get("explanation", "")
                chain_text = "Attack chain detected: " + "; ".join(chain_descriptions[:2])
                finding["explanation"] = (
                    f"{chain_text}. {existing_explanation}" if existing_explanation else chain_text
                )

    return findings


def detect_multi_vector_endpoints(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Identify endpoints flagged by multiple independent detection modules.

    Args:
        findings: List of finding dicts with correlation metadata.

    Returns:
        List of endpoint summaries with multi-vector details, sorted by risk.
    """
    endpoint_summary: dict[str, dict[str, Any]] = {}

    for finding in findings:
        url = str(finding.get("url", ""))
        endpoint_key = str(
            (finding.get("evidence", {}) or {}).get("endpoint_base_key")
            or (finding.get("evidence", {}) or {}).get("endpoint_key")
            or url
        )

        if endpoint_key not in endpoint_summary:
            parsed = urlparse(url)
            endpoint_summary[endpoint_key] = {
                "endpoint_key": endpoint_key,
                "url": url,
                "host": parsed.netloc,
                "finding_count": 0,
                "categories": set(),
                "modules": set(),
                "max_severity": "low",
                "attack_chains": [],
                "compound_risk_score": 0,
                "findings": [],
            }

        summary = endpoint_summary[endpoint_key]
        summary["finding_count"] += 1
        summary["categories"].add(finding.get("category", ""))
        summary["modules"].add(finding.get("module", ""))
        summary["findings"].append(finding)

        # Track max severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        current_sev = severity_order.get(finding.get("severity", "low"), 0)
        max_sev = severity_order.get(summary["max_severity"], 0)
        if current_sev > max_sev:
            summary["max_severity"] = finding.get("severity", "low")

        # Track attack chains
        for chain in finding.get("attack_chains", []):
            if chain not in summary["attack_chains"]:
                summary["attack_chains"].append(chain)

        # Track compound risk
        summary["compound_risk_score"] = max(
            summary["compound_risk_score"],
            finding.get("compound_risk_score", 0),
        )

    # Convert to list and sort by compound risk
    result = []
    for summary in endpoint_summary.values():
        if summary["finding_count"] < 2:
            continue
        typed_summary = {
            **summary,
            "categories": sorted(summary["categories"] - {""}),
            "modules": sorted(summary["modules"] - {""}),
            "multi_vector_score": round(
                min(summary["finding_count"] * 0.15 + len(summary["attack_chains"]) * 0.2, 1.0),
                2,
            ),
        }
        independent_vectors = max(
            len(typed_summary["categories"]),
            len(typed_summary["modules"]),
        )
        if independent_vectors >= 2:
            result.append(typed_summary)

    result.sort(key=lambda x: (-x["compound_risk_score"], -x["finding_count"]))
    return result


def calculate_compound_risk(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate overall compound risk metrics for a findings set.

    Args:
        findings: List of finding dicts with correlation metadata.

    Returns:
        Dict with compound risk metrics including:
        - total_findings: total number of findings
        - multi_vector_endpoints: count of endpoints with multiple findings
        - attack_chains_detected: count of detected attack chains
        - highest_compound_risk: highest compound risk score
        - risk_distribution: breakdown by severity
    """
    multi_vector_count = sum(1 for f in findings if f.get("multi_vector"))
    all_chains: set[str] = set()
    max_compound = 0

    for finding in findings:
        for chain in finding.get("attack_chains", []):
            all_chains.add(chain)
        max_compound = max(max_compound, finding.get("compound_risk_score", 0))

    severity_counts: dict[str, int] = defaultdict(int)
    for finding in findings:
        severity_counts[finding.get("severity", "low")] += 1

    return {
        "total_findings": len(findings),
        "multi_vector_findings": multi_vector_count,
        "attack_chains_detected": len(all_chains),
        "attack_chain_names": sorted(all_chains),
        "highest_compound_risk": max_compound,
        "risk_distribution": dict(severity_counts),
        "correlation_coverage": round(multi_vector_count / max(len(findings), 1), 2),
    }
