import html
from typing import Any

from src.reporting.sections_campaigns import campaign_summary_section
from src.reporting.sections_findings import (
    graphql_findings_section,
    high_confidence_shortlist_section,
    manual_verification_section,
    signal_quality_section,
    top_findings_section,
    verified_exploits_section,
)
from src.reporting.sections_general import (
    analysis_section,
    attack_graph_section,
    auth_context_mapping_section,
    behavior_analysis_section,
    count_cards,
    detection_gap_section,
    diff_cards,
    endpoint_relationship_graph_section,
    finding_graph_section,
    flow_detection_section,
    high_value_section,
    list_section,
    module_metrics_section,
    next_steps_section,
    prioritized_endpoints_section,
    response_diff_section,
    response_snapshot_section,
    screenshot_section,
    shared_parameter_tracking_section,
    stat_grid_section,
    technology_section,
    validation_plan_section,
    vrt_coverage_section,
)
from src.reporting.sections_validation import (
    exposed_api_keys_section,
    validation_results_section,
)

__all__ = [
    "analysis_section",
    "attack_graph_section",
    "auth_context_mapping_section",
    "behavior_analysis_section",
    "build_executive_summary",
    "campaign_summary_section",
    "count_cards",
    "detection_gap_section",
    "diff_cards",
    "endpoint_relationship_graph_section",
    "exposed_api_keys_section",
    "finding_graph_section",
    "flow_detection_section",
    "graphql_findings_section",
    "high_confidence_shortlist_section",
    "high_value_section",
    "list_section",
    "manual_verification_section",
    "module_metrics_section",
    "next_steps_section",
    "prioritized_endpoints_section",
    "response_diff_section",
    "response_snapshot_section",
    "screenshot_section",
    "shared_parameter_tracking_section",
    "signal_quality_section",
    "stat_grid_section",
    "technology_section",
    "validation_plan_section",
    "top_findings_section",
    "validation_results_section",
    "verified_exploits_section",
    "vrt_coverage_section",
]

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "info": 1,
}

SEVERITY_COLOR_MAP: dict[str, str] = {
    "critical": "#cc0000",
    "high": "#ff6600",
    "medium": "#ffcc00",
    "low": "#66bb6a",
    "info": "#959595",
}


def _calculate_risk_score(findings: list[dict[str, Any]]) -> float:
    if not findings:
        return 0.0
    total = sum(SEVERITY_WEIGHTS.get(str(f.get("severity", "info")).lower(), 1) for f in findings)
    return min(round(total / max(1, len(findings)), 1), 10.0)


def _risk_level(score: float) -> tuple[str, str]:
    if score >= 8:
        return "Critical", SEVERITY_COLOR_MAP["critical"]
    if score >= 6:
        return "High", SEVERITY_COLOR_MAP["high"]
    if score >= 4:
        return "Medium", SEVERITY_COLOR_MAP["medium"]
    if score >= 2:
        return "Low", SEVERITY_COLOR_MAP["low"]
    return "Minimal", SEVERITY_COLOR_MAP["info"]


def _severity_distribution(findings: list[dict[str, Any]]) -> dict[str, int]:
    dist: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        dist[sev] = dist.get(sev, 0) + 1
    return dist


def build_executive_summary(
    summary: dict[str, Any],
    summary_data: dict[str, Any],
    diff_summary: dict[str, Any] | None = None,
) -> str:
    all_findings = summary.get("top_actionable_findings", []) + summary.get("verified_exploits", [])
    risk_score = _calculate_risk_score(all_findings)
    risk_label, risk_color = _risk_level(risk_score)

    critical_findings = [
        f for f in all_findings if str(f.get("severity", "")).lower() in ("critical", "high")
    ][:5]

    subdomain_count = len(summary.get("subdomains", set()))
    live_host_count = len(summary.get("live_hosts", set()))
    url_count = len(summary.get("urls", set()))

    trend_line = ""
    if diff_summary:
        prev_counts = diff_summary.get("previous_counts", {})
        curr_counts = diff_summary.get("current_counts", {})
        total_prev = sum(v for v in prev_counts.values() if isinstance(v, (int, float)))
        total_curr = sum(v for v in curr_counts.values() if isinstance(v, (int, float)))
        if total_prev > 0:
            delta = total_curr - total_prev
            sign = "+" if delta >= 0 else ""
            trend_line = (
                "<div class='trend-comparison'>"
                "<h3>Run Comparison</h3>"
                f"<span class='trend-text'>Findings changed by {sign}{delta} "
                f"(previous: {total_prev}, current: {total_curr})</span>"
                "</div>"
            )

    critical_cards = ""
    for f in critical_findings:
        sev = html.escape(str(f.get("severity", "info")).upper())
        title = html.escape(f.get("title", "Finding"))
        url = html.escape(f.get("url", ""))
        impact = html.escape(
            f.get("business_impact", f.get("explanation", "Potential security risk identified"))
        )
        critical_cards += (
            "<li class='critical-finding-card'>"
            f"<span class='sev-badge' style='background:{SEVERITY_COLOR_MAP.get(str(f.get('severity', 'info')).lower(), '#959595')};color:#fff;padding:2px 6px;border-radius:3px;font-size:0.8em;'>{sev}</span> "
            f"<strong>{title}</strong><br>"
            f"<span class='muted'>{url}</span><br>"
            f"<span class='impact-text'>{impact}</span>"
            "</li>"
        )
    if not critical_cards:
        critical_cards = (
            "<li><span class='muted'>No critical or high severity findings.</span></li>"
        )

    severity_dist = _severity_distribution(all_findings)
    severity_bars = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        cnt = severity_dist.get(sev, 0)
        color = SEVERITY_COLOR_MAP.get(sev, "#959595")
        severity_bars += (
            f"<div class='sev-bar-row'>"
            f"<span class='sev-label' style='background:{color};color:#fff;padding:2px 6px;border-radius:3px;font-size:0.8em;'>{sev.upper()}</span>"
            f"<span class='sev-count'>{cnt}</span>"
            "</div>"
        )

    recon_cards = (
        f"<div class='recon-card'><div class='recon-label'>Subdomains Discovered</div>"
        f"<div class='recon-value'>{subdomain_count}</div></div>"
        f"<div class='recon-card'><div class='recon-label'>Live Hosts</div>"
        f"<div class='recon-value'>{live_host_count}</div></div>"
        f"<div class='recon-card'><div class='recon-label'>URLs Collected</div>"
        f"<div class='recon-value'>{url_count}</div></div>"
    )

    return (
        "<section class='executive-summary'>"
        "<h2>Executive Summary</h2>"
        "<div class='risk-overview'>"
        f"<div class='risk-score-circle' style='border-color:{risk_color};color:{risk_color};'>"
        f"<span class='risk-number'>{risk_score}</span>"
        f"<span class='risk-severity'>{html.escape(risk_label)}</span>"
        "</div>"
        "<div class='severity-distribution'>"
        "<h3>Severity Distribution</h3>"
        f"{severity_bars}"
        "</div>"
        "</div>"
        "<div class='recon-coverage'>"
        "<h3>Recon Coverage</h3>"
        f"<div class='recon-grid'>{recon_cards}</div>"
        "</div>"
        "<div class='top-critical'>"
        "<h3>Top Critical Findings</h3>"
        f"<ul>{critical_cards}</ul>"
        "</div>"
        f"{trend_line}"
        "</section>"
    )
