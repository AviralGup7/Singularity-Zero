"""Detection coverage metrics for security reports.

Analyzes which vulnerability categories were tested, which found issues,
and identifies coverage gaps to provide visibility into the thoroughness
of the security assessment.
"""

import html
from typing import Any

# Complete list of detection categories the pipeline can test
ALL_DETECTION_CATEGORIES: dict[str, dict[str, str]] = {
    "idor": {
        "name": "Insecure Direct Object Reference",
        "severity_potential": "High",
        "test_type": "Passive + Active",
    },
    "ssrf": {
        "name": "Server-Side Request Forgery",
        "severity_potential": "Critical",
        "test_type": "Passive + Active",
    },
    "xss": {
        "name": "Cross-Site Scripting",
        "severity_potential": "High",
        "test_type": "Passive + Active",
    },
    "open_redirect": {
        "name": "Open Redirect",
        "severity_potential": "Medium",
        "test_type": "Passive + Active",
    },
    "token_leak": {
        "name": "Token/Session Exposure",
        "severity_potential": "High",
        "test_type": "Passive",
    },
    "access_control": {
        "name": "Access Control Bypass",
        "severity_potential": "High",
        "test_type": "Passive + Active",
    },
    "authentication_bypass": {
        "name": "Authentication Bypass",
        "severity_potential": "Critical",
        "test_type": "Passive + Active",
    },
    "broken_authentication": {
        "name": "Broken Authentication",
        "severity_potential": "High",
        "test_type": "Passive",
    },
    "business_logic": {
        "name": "Business Logic Flaws",
        "severity_potential": "High",
        "test_type": "Active",
    },
    "payment": {
        "name": "Payment Flow Issues",
        "severity_potential": "High",
        "test_type": "Passive",
    },
    "sensitive_data": {
        "name": "Sensitive Data Exposure",
        "severity_potential": "High",
        "test_type": "Passive",
    },
    "misconfiguration": {
        "name": "Security Misconfiguration",
        "severity_potential": "Medium",
        "test_type": "Passive",
    },
    "cors": {
        "name": "CORS Misconfiguration",
        "severity_potential": "Medium",
        "test_type": "Passive + Active",
    },
    "session": {"name": "Session Management", "severity_potential": "High", "test_type": "Passive"},
    "anomaly": {
        "name": "Anomalous Behavior",
        "severity_potential": "Medium",
        "test_type": "Passive",
    },
    "behavioral_deviation": {
        "name": "Behavioral Deviation",
        "severity_potential": "Medium",
        "test_type": "Active",
    },
    "redirect": {
        "name": "Redirect Issues",
        "severity_potential": "Medium",
        "test_type": "Passive + Active",
    },
    "server_side_injection": {
        "name": "Server-Side Injection",
        "severity_potential": "Critical",
        "test_type": "Active",
    },
    "race_condition": {
        "name": "Race Condition",
        "severity_potential": "High",
        "test_type": "Passive",
    },
    "csrf": {
        "name": "Cross-Site Request Forgery",
        "severity_potential": "Medium",
        "test_type": "Passive",
    },
    "ssti": {
        "name": "Server-Side Template Injection",
        "severity_potential": "Critical",
        "test_type": "Passive",
    },
    "ai_surface": {
        "name": "AI/ML Surface Exposure",
        "severity_potential": "Medium",
        "test_type": "Passive",
    },
    "exposure": {
        "name": "Information Exposure",
        "severity_potential": "Low",
        "test_type": "Passive",
    },
}


def detection_coverage_section(
    findings: list[dict[str, Any]],
    analysis_results: dict[str, list[dict[str, Any]]],
    validation_summary: dict[str, Any] | None = None,
) -> str:
    """Generate a detection coverage section for the security report.

    Shows which vulnerability categories were tested, which found issues,
    and identifies coverage gaps.

    Args:
        findings: List of finding dicts from merge_findings().
        analysis_results: Dict of module_name -> list of results.
        validation_summary: Optional validation results.

    Returns:
        HTML string for the detection coverage section.
    """
    # Determine which categories were tested (modules that ran)
    tested_categories: set[str] = set()
    module_to_category: dict[str, str] = {
        "idor_candidate_finder": "idor",
        "ssrf_candidate_finder": "ssrf",
        "token_leak_detector": "token_leak",
        "sensitive_field_detector": "sensitive_data",
        "anomaly_detector": "anomaly",
        "behavior_analysis_layer": "behavioral_deviation",
        "header_checker": "misconfiguration",
        "cookie_security_checker": "misconfiguration",
        "cors_misconfig_checker": "cors",
        "cache_control_checker": "misconfiguration",
        "stored_xss_signal_detector": "xss",
        "reflected_xss_probe": "xss",
        "race_condition_signal_analyzer": "race_condition",
        "parameter_pollution_exploitation": "business_logic",
        "auth_header_tampering_variations": "authentication_bypass",
        "http_method_override_probe": "authentication_bypass",
        "json_mutation_attacks": "business_logic",
        "post_body_mutation_attacks": "business_logic",
        "multi_step_flow_breaking_probe": "business_logic",
        "redirect_chain_analyzer": "redirect",
        "auth_boundary_redirect_detection": "redirect",
        "open_redirect_validation": "open_redirect",
        "ssrf_validation": "ssrf",
        "idor_validation": "idor",
        "token_reuse_validation": "token_leak",
        "csrf_protection_checker": "csrf",
        "ssti_surface_detector": "ssti",
        "ai_endpoint_exposure_analyzer": "ai_surface",
        "payment_flow_intelligence": "payment",
        "payment_provider_detection": "payment",
        "session_reuse_detection": "session",
        "logout_invalidation_check": "session",
        "cross_user_access_simulation": "access_control",
        "role_based_endpoint_comparison": "access_control",
        "privilege_escalation_detector": "access_control",
        "access_boundary_tracker": "access_control",
        "unauth_access_check": "authentication_bypass",
        "error_stack_trace_detector": "exposure",
        "environment_file_exposure_checker": "exposure",
        "backup_file_exposure_checker": "exposure",
        "graphql_introspection_exposure_checker": "exposure",
        "graphql_introspection_check": "graphql_vulnerability",
        "graphql_active_probe": "graphql",
        "openapi_swagger_spec_checker": "exposure",
        "server_side_injection_surface_analyzer": "server_side_injection",
    }

    for module_name in analysis_results:
        if module_name in module_to_category:
            tested_categories.add(module_to_category[module_name])

    # Determine which categories found issues
    categories_with_findings: dict[str, int] = {}
    for finding in findings:
        cat = str(finding.get("category", "")).lower()
        if cat in ALL_DETECTION_CATEGORIES:
            categories_with_findings[cat] = categories_with_findings.get(cat, 0) + 1

    # Build coverage table
    rows: list[str] = []
    tested_count = 0
    findings_count = 0
    gaps: list[str] = []

    for category, info in sorted(ALL_DETECTION_CATEGORIES.items()):
        was_tested = category in tested_categories
        has_findings = category in categories_with_findings
        finding_count = categories_with_findings.get(category, 0)

        if was_tested:
            tested_count += 1
        if has_findings:
            findings_count += finding_count

        # Status indicator
        if has_findings:
            status = (
                f'<span class="coverage-status status-findings">⚠️ {finding_count} finding(s)</span>'
            )
        elif was_tested:
            status = '<span class="coverage-status status-clean">✅ Tested - No issues</span>'
        else:
            status = '<span class="coverage-status status-not-tested">⬜ Not tested</span>'
            gaps.append(info["name"])

        rows.append(
            f"<tr>"
            f"<td>{html.escape(info['name'])}</td>"
            f"<td><code>{html.escape(category)}</code></td>"
            f"<td>{html.escape(info['severity_potential'])}</td>"
            f"<td>{html.escape(info['test_type'])}</td>"
            f"<td>{status}</td>"
            f"</tr>"
        )

    # Calculate coverage percentage
    total_categories = len(ALL_DETECTION_CATEGORIES)
    coverage_pct = round(tested_count / max(total_categories, 1) * 100)

    # Build gap summary
    gap_summary = ""
    if gaps:
        gap_list = ", ".join(gaps[:10])
        if len(gaps) > 10:
            gap_list += f" and {len(gaps) - 10} more"
        gap_summary = (
            f"<div class='coverage-gaps'>"
            f"<h4>Coverage Gaps</h4>"
            f"<p>The following vulnerability categories were not tested in this run: {html.escape(gap_list)}.</p>"
            f"<p>Consider enabling relevant modules or providing additional input data to improve coverage.</p>"
            f"</div>"
        )

    return (
        "<section class='detection-coverage'>"
        "<h2>Detection Coverage</h2>"
        f"<div class='coverage-summary'>"
        f"<div class='coverage-stat'><strong>{tested_count}</strong> / {total_categories} categories tested ({coverage_pct}%)</div>"
        f"<div class='coverage-stat'><strong>{findings_count}</strong> total findings across {len(categories_with_findings)} categories</div>"
        f"</div>"
        f"<table class='coverage-table'>"
        f"<thead><tr><th>Category</th><th>ID</th><th>Severity Potential</th><th>Test Type</th><th>Status</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        f"</table>"
        f"{gap_summary}"
        "</section>"
    )
