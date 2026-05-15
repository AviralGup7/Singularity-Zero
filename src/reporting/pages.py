import html
import json
from pathlib import Path
from typing import Any

from src.core.utils import IST_LABEL, format_iso_to_ist
from src.reporting.assets import INDEX_STYLES, REPORT_SCRIPT, RUN_REPORT_STYLES
from src.reporting.sections import (
    analysis_section,
    attack_graph_section,
    auth_context_mapping_section,
    behavior_analysis_section,
    build_executive_summary,
    campaign_summary_section,
    count_cards,
    detection_gap_section,
    diff_cards,
    endpoint_relationship_graph_section,
    exposed_api_keys_section,
    finding_graph_section,
    flow_detection_section,
    high_confidence_shortlist_section,
    high_value_section,
    list_section,
    manual_verification_section,
    module_metrics_section,
    next_steps_section,
    prioritized_endpoints_section,
    response_diff_section,
    response_snapshot_section,
    screenshot_section,
    shared_parameter_tracking_section,
    signal_quality_section,
    stat_grid_section,
    technology_section,
    top_findings_section,
    validation_plan_section,
    validation_results_section,
    verified_exploits_section,
    vrt_coverage_section,
)


def generate_run_report(
    run_dir: Path,
    summary: dict[str, Any],
    diff_summary: dict[str, Any] | None,
    screenshots: list[dict[str, Any]],
    priority_urls: set[str],
    parameters: set[str],
    analysis_results: dict[str, list[dict[str, Any]]],
) -> None:
    generated_at = str(summary.get("generated_at_ist", "")).strip() or format_iso_to_ist(
        str(summary.get("generated_at_utc", "")).strip()
    )
    previous_line = (
        f"<p class='muted'>Compared with previous run: {html.escape(diff_summary['previous_run'])}</p>"
        if diff_summary
        else "<p class='muted'>This is the first recorded run for this target.</p>"
    )
    sections = [
        build_executive_summary(summary, summary, diff_summary),
        f"<section><h2>Run Counts</h2><div class='grid'>{count_cards(summary)}</div></section>",
        stat_grid_section(
            "Target Profile", summary.get("target_profile", {}), "No adaptive profile available."
        ),
        technology_section(summary),
        vrt_coverage_section(summary),
        campaign_summary_section(summary),
        stat_grid_section(
            "Attack Surface Summary", summary.get("attack_surface", {}), "No summary available."
        ),
        stat_grid_section("Trends", summary.get("trend_summary", {}), "No trend data available."),
        module_metrics_section(summary),
        detection_gap_section(summary, analysis_results),
        prioritized_endpoints_section(summary),
        attack_graph_section(summary),
        endpoint_relationship_graph_section(summary),
        finding_graph_section(summary),
        validation_plan_section(summary),
        shared_parameter_tracking_section(summary),
        auth_context_mapping_section(summary),
        top_findings_section(summary),
        high_confidence_shortlist_section(summary),
        manual_verification_section(summary),
        signal_quality_section(summary),
        flow_detection_section(analysis_results),
        response_snapshot_section(analysis_results),
        response_diff_section(analysis_results),
        behavior_analysis_section(analysis_results),
        validation_results_section(summary),
        exposed_api_keys_section(summary, analysis_results),
        verified_exploits_section(summary),
        next_steps_section(summary),
        f"<section><h2>Diff Snapshot</h2><div class='grid'>{diff_cards(diff_summary)}</div></section>",
        high_value_section(summary.get("high_value_endpoints", [])),
        list_section("Priority Endpoints", sorted(priority_urls)),
        list_section("Parameters", sorted(parameters)),
        analysis_section(
            "Sensitive Data Scanner", analysis_results.get("sensitive_data_scanner", [])
        ),
        analysis_section("Header Checker", analysis_results.get("header_checker", [])),
        analysis_section(
            "Cookie Security Checker", analysis_results.get("cookie_security_checker", [])
        ),
        analysis_section(
            "Passive CORS Checker", analysis_results.get("cors_misconfig_checker", [])
        ),
        analysis_section(
            "Cache Control Checker", analysis_results.get("cache_control_checker", [])
        ),
        analysis_section(
            "JSONP Endpoint Checker", analysis_results.get("jsonp_endpoint_checker", [])
        ),
        analysis_section(
            "Frontend Config Exposure Checker",
            analysis_results.get("frontend_config_exposure_checker", []),
        ),
        analysis_section(
            "Directory Listing Checker", analysis_results.get("directory_listing_checker", [])
        ),
        analysis_section(
            "Debug Artifact Checker", analysis_results.get("debug_artifact_checker", [])
        ),
        analysis_section(
            "Stored XSS Signal Detector", analysis_results.get("stored_xss_signal_detector", [])
        ),
        analysis_section(
            "AI Endpoint Exposure Analyzer",
            analysis_results.get("ai_endpoint_exposure_analyzer", []),
        ),
        analysis_section("Token Leak Detector", analysis_results.get("token_leak_detector", [])),
        analysis_section(
            "IDOR Candidate Finder", analysis_results.get("idor_candidate_finder", [])
        ),
        analysis_section(
            "Parameter Pollution Exploitation",
            analysis_results.get("parameter_pollution_exploitation", []),
        ),
        analysis_section(
            "Auth Header Tampering Variations",
            analysis_results.get("auth_header_tampering_variations", []),
        ),
        analysis_section(
            "HTTP Method Override Probe", analysis_results.get("http_method_override_probe", [])
        ),
        analysis_section(
            "JSON Mutation Attacks", analysis_results.get("json_mutation_attacks", [])
        ),
        analysis_section(
            "Multi-Step Flow Breaking Probe",
            analysis_results.get("multi_step_flow_breaking_probe", []),
        ),
        analysis_section(
            "Smart Payload Suggestions", analysis_results.get("smart_payload_suggestions", [])
        ),
        analysis_section("JSON Response Parser", analysis_results.get("json_response_parser", [])),
        analysis_section(
            "JSON Schema Inference", analysis_results.get("json_schema_inference", [])
        ),
        analysis_section(
            "Sensitive Field Detector", analysis_results.get("sensitive_field_detector", [])
        ),
        analysis_section(
            "Cross-Tenant PII Risk Analyzer",
            analysis_results.get("cross_tenant_pii_risk_analyzer", []),
        ),
        analysis_section(
            "Cross-User Access Simulation", analysis_results.get("cross_user_access_simulation", [])
        ),
        analysis_section(
            "Role-Based Endpoint Comparison",
            analysis_results.get("role_based_endpoint_comparison", []),
        ),
        analysis_section(
            "Privilege Escalation Detector",
            analysis_results.get("privilege_escalation_detector", []),
        ),
        analysis_section(
            "Access Boundary Tracker", analysis_results.get("access_boundary_tracker", [])
        ),
        analysis_section(
            "Nested Object Traversal", analysis_results.get("nested_object_traversal", [])
        ),
        analysis_section(
            "Endpoint Resource Groups", analysis_results.get("endpoint_resource_groups", [])
        ),
        analysis_section(
            "Bulk Endpoint Detector", analysis_results.get("bulk_endpoint_detector", [])
        ),
        analysis_section("Pagination Walker", analysis_results.get("pagination_walker", [])),
        analysis_section(
            "Filter Parameter Fuzzer", analysis_results.get("filter_parameter_fuzzer", [])
        ),
        analysis_section(
            "Error-Based Inference", analysis_results.get("error_based_inference", [])
        ),
        analysis_section(
            "Session Reuse Detection", analysis_results.get("session_reuse_detection", [])
        ),
        analysis_section(
            "Logout Invalidation Check", analysis_results.get("logout_invalidation_check", [])
        ),
        analysis_section(
            "Multi-Endpoint Auth Consistency Check",
            analysis_results.get("multi_endpoint_auth_consistency_check", []),
        ),
        analysis_section("Token Scope Analyzer", analysis_results.get("token_scope_analyzer", [])),
        analysis_section(
            "Referer Propagation Tracking", analysis_results.get("referer_propagation_tracking", [])
        ),
        analysis_section(
            "State Transition Analyzer", analysis_results.get("state_transition_analyzer", [])
        ),
        analysis_section(
            "Parameter Dependency Tracker", analysis_results.get("parameter_dependency_tracker", [])
        ),
        analysis_section(
            "Flow Integrity Checker", analysis_results.get("flow_integrity_checker", [])
        ),
        analysis_section(
            "Server-Side Injection Surface Analyzer",
            analysis_results.get("server_side_injection_surface_analyzer", []),
        ),
        analysis_section(
            "Race Condition Signal Analyzer",
            analysis_results.get("race_condition_signal_analyzer", []),
        ),
        analysis_section("Version Diffing", analysis_results.get("version_diffing", [])),
        analysis_section("Role Context Diff", analysis_results.get("role_context_diff", [])),
        analysis_section("Unauth Access Check", analysis_results.get("unauth_access_check", [])),
        analysis_section(
            "Rate Limit Signal Analyzer", analysis_results.get("rate_limit_signal_analyzer", [])
        ),
        analysis_section(
            "Response Size Anomaly Detector",
            analysis_results.get("response_size_anomaly_detector", []),
        ),
        analysis_section(
            "Port Scan Integration", analysis_results.get("port_scan_integration", [])
        ),
        analysis_section(
            "Service Fingerprinting", analysis_results.get("service_fingerprinting", [])
        ),
        analysis_section(
            "Default Credential Hints", analysis_results.get("default_credential_hints", [])
        ),
        analysis_section(
            "Exposed Service Detection", analysis_results.get("exposed_service_detection", [])
        ),
        analysis_section(
            "TLS SSL Misconfiguration Checks",
            analysis_results.get("tls_ssl_misconfiguration_checks", []),
        ),
        analysis_section(
            "Nonstandard Service Index Detection",
            analysis_results.get("nonstandard_service_index_detection", []),
        ),
        analysis_section(
            "Subdomain Port Mapping", analysis_results.get("subdomain_port_mapping", [])
        ),
        analysis_section(
            "Admin Panel Path Detection", analysis_results.get("admin_panel_path_detection", [])
        ),
        analysis_section(
            "HTTP Title Clustering", analysis_results.get("http_title_clustering", [])
        ),
        analysis_section(
            "Dev Staging Environment Detection",
            analysis_results.get("dev_staging_environment_detection", []),
        ),
        analysis_section(
            "Payment Flow Intelligence", analysis_results.get("payment_flow_intelligence", [])
        ),
        analysis_section(
            "Payment Provider Detection", analysis_results.get("payment_provider_detection", [])
        ),
        analysis_section(
            "Behavior Analysis Layer", analysis_results.get("behavior_analysis_layer", [])
        ),
        analysis_section("OPTIONS Method Probe", analysis_results.get("options_method_probe", [])),
        analysis_section(
            "Origin Reflection Probe", analysis_results.get("origin_reflection_probe", [])
        ),
        analysis_section("HEAD Method Probe", analysis_results.get("head_method_probe", [])),
        analysis_section("CORS Preflight Probe", analysis_results.get("cors_preflight_probe", [])),
        analysis_section("TRACE Method Probe", analysis_results.get("trace_method_probe", [])),
        analysis_section("Reflected XSS Probe", analysis_results.get("reflected_xss_probe", [])),
        analysis_section(
            "Redirect Chain Analyzer", analysis_results.get("redirect_chain_analyzer", [])
        ),
        analysis_section(
            "Auth-Boundary Redirect Detection",
            analysis_results.get("auth_boundary_redirect_detection", []),
        ),
        screenshot_section(screenshots),
    ]
    target_name = summary.get("target_name", "")
    export_header = (
        "<div class='export-bar'>"
        f"<span class='export-label'>Export findings:</span>"
        f"<a class='export-btn' href='/api/export/findings/{html.escape(target_name)}/latest?format=csv' download>CSV (latest run)</a>"
        f"<a class='export-btn' href='/api/export/findings/{html.escape(target_name)}/latest?format=json' download>JSON (latest run)</a>"
        f"<a class='export-btn' href='/api/export/findings/{html.escape(target_name)}?format=csv' download>CSV (all runs)</a>"
        f"<a class='export-btn' href='/api/export/findings/{html.escape(target_name)}?format=json' download>JSON (all runs)</a>"
        "</div>"
    )
    page = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>{html.escape(summary['target_name'])} report</title><style>{RUN_REPORT_STYLES}</style></head><body><main>"
        f"<h1>{html.escape(summary['target_name'])}</h1>"
        f"<p class='muted'>Generated at {html.escape(generated_at)} ({html.escape(IST_LABEL)})</p>{previous_line}"
        f"{export_header}"
        f"{''.join(sections)}</main><script>{REPORT_SCRIPT}</script></body></html>"
    )
    (run_dir / "report.html").write_text(page, encoding="utf-8")


def build_dashboard_index(target_root: Path, run_dirs: list[Path]) -> None:
    rows = []
    for run_dir in reversed(run_dirs):
        summary = json.loads((run_dir / "run_summary.json").read_text(encoding="utf-8"))
        generated_at = str(summary.get("generated_at_ist", "")).strip() or format_iso_to_ist(
            str(summary.get("generated_at_utc", "")).strip()
        )
        diff = None
        if (run_dir / "diff_summary.json").exists():
            diff = json.loads((run_dir / "diff_summary.json").read_text(encoding="utf-8"))
        counts = "".join(
            f"<span class='chip'>{html.escape(key.replace('_', ' '))}: {value}</span>"
            for key, value in summary["counts"].items()
        )
        diff_line = ""
        if diff:
            added = sum(info["added_count"] for info in diff["artifacts"].values())
            removed = sum(info["removed_count"] for info in diff["artifacts"].values())
            diff_line = (
                f"<p class='muted'>Delta across tracked artifacts: +{added} / -{removed}</p>"
            )
        rows.append(
            "<div class='run'>"
            f"<h2>{html.escape(run_dir.name)}</h2>"
            f"<p class='muted'>Generated at {html.escape(generated_at)} ({html.escape(IST_LABEL)})</p>"
            f"<div class='counts'>{counts}</div>{diff_line}"
            f"<p><a href='{html.escape(run_dir.name)}/report.html'>Open report</a></p>"
            f"<div class='export-row'>"
            f"<a class='export-btn' href='/api/export/findings/{html.escape(target_root.name)}/latest?format=csv' download>CSV</a>"
            f"<a class='export-btn' href='/api/export/findings/{html.escape(target_root.name)}/latest?format=json' download>JSON</a>"
            f"<a class='export-btn' href='/api/export/findings/{html.escape(target_root.name)}?format=csv' download>All CSV</a>"
            f"<a class='export-btn' href='/api/export/findings/{html.escape(target_root.name)}?format=json' download>All JSON</a>"
            "</div></div>"
        )
    empty = "<p class='muted'>No runs yet.</p>"
    page = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>{html.escape(target_root.name)} dashboard</title><style>{INDEX_STYLES}</style></head><body><main>"
        f"<h1>{html.escape(target_root.name)} Dashboard</h1>"
        "<p class='muted'>Serve this directory with dashboard.py or any static file server.</p>"
        f"{''.join(rows) if rows else empty}</main></body></html>"
    )
    (target_root / "index.html").write_text(page, encoding="utf-8")
