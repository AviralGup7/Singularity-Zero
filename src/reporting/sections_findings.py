"""HTML report findings section layout generators."""

from __future__ import annotations

import html
from typing import Any

from src.intelligence.severity_model import enrich_findings_with_model_severity

# Modularized badge imports
from src.reporting.finding_badges import (
    render_attack_chain_badge,
    render_correlation_badge,
    render_cvss_badge,
    render_mitre_badge_for_access_control,
    render_mitre_badge_for_auth_bypass,
    render_mitre_badges,
    render_model_badge,
)

# Modularized grid imports
from src.reporting.finding_grids import (
    observed_result_grid,
    review_summary_grid,
)


def top_findings_section(summary: dict[str, Any]) -> str:
    """Generate the HTML section for top actionable findings."""
    items = enrich_findings_with_model_severity(summary.get("top_actionable_findings", []))
    if not items:
        return "<section><h2>Top Actionable Findings</h2><p class='muted'>No prioritized findings yet.</p></section>"
    rows = []
    seen_endpoints: set[str] = set()
    for item in items:
        endpoint_key = str(item.get("evidence", {}).get("endpoint_key") or item.get("url", ""))
        if endpoint_key in seen_endpoints:
            continue
        seen_endpoints.add(endpoint_key)
        # Build explanation from score_breakdown if available
        explanation_parts = []
        score_breakdown = item.get("score_breakdown")
        if isinstance(score_breakdown, dict):
            for key, value in score_breakdown.items():
                if isinstance(value, (int, float)) and value > 0:
                    readable_key = key.replace("_", " ").title()
                    explanation_parts.append(f"{readable_key}: {value}")
        explanation_text = item.get("explanation", "")
        if explanation_parts:
            explanation_text = ("; ".join(explanation_parts) + ". " + explanation_text).strip()
        rows.append(
            "<li>"
            f"<strong>{html.escape(str(item.get('severity', 'info')).upper())}</strong> "
            f"{html.escape(item.get('title', 'Finding'))} "
            f"{render_model_badge(item)} "
            f"{render_cvss_badge(item)}"
            f"{render_attack_chain_badge(item)}"
            f"<span class='muted'>score {html.escape(str(item.get('score', 0)))} | confidence {html.escape(str(round(float(item.get('confidence', 0)) * 100)))}% | {html.escape(str(item.get('history_status', 'new')))}</span><br>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>{html.escape(explanation_text)}</span>"
            f"{render_mitre_badges(item.get('mitre_attack', []))}"
            f"{render_correlation_badge(item)}"
            "</li>"
        )
        if len(rows) >= 5:
            break
    return f"<section><h2>Top Actionable Findings</h2><ul>{''.join(rows)}</ul></section>"


def high_confidence_shortlist_section(summary: dict[str, Any]) -> str:
    """Generate HTML section for high-confidence findings shortlist."""
    items = enrich_findings_with_model_severity(summary.get("high_confidence_shortlist", []))
    if not items:
        return "<section><h2>High-Confidence Shortlist</h2><p class='muted'>No shortlist entries yet.</p></section>"
    rows = [
        "<li>"
        f"<strong>{html.escape(str(item.get('severity', 'info')).upper())}</strong> "
        f"{html.escape(item.get('title', 'Shortlist item'))} "
        f"{render_model_badge(item)}"
        f"<span class='muted'>{html.escape(str(item.get('category', 'unknown')))} | confidence {html.escape(str(round(float(item.get('confidence', 0)) * 100)))}% | {html.escape(str(item.get('history_status', 'new')))}</span><br>"
        f"{html.escape(item.get('url', ''))}<br>"
        f"<span class='muted'>{html.escape(item.get('explanation', item.get('next_step', '')))}</span>"
        "</li>"
        for item in items[:5]
    ]
    return f"<section><h2>High-Confidence Shortlist</h2><ul>{''.join(rows)}</ul></section>"


def manual_verification_section(summary: dict[str, Any]) -> str:
    """Generate HTML section for the manual verification queue."""
    items = enrich_findings_with_model_severity(summary.get("manual_verification_queue", []))
    if not items:
        return "<section><h2>Manual Verification Queue</h2><p class='muted'>No queued review tasks.</p></section>"
    rows = []
    for item in items:
        review_brief = html.escape(item.get("review_brief", ""), quote=True)
        review_url = html.escape(item.get("url", ""), quote=True)
        replay_url = html.escape(item.get("replay_url", ""), quote=True)
        anonymous_replay_url = html.escape(item.get("anonymous_replay_url", ""), quote=True)
        poc_curl = html.escape(item.get("poc_curl", ""), quote=True)
        poc_python = html.escape(item.get("poc_python", ""), quote=True)
        chain_summary = html.escape(item.get("chain_summary", ""), quote=True)
        is_api_replay_candidate = bool(item.get("is_api_replay_candidate"))
        sq = chr(39)
        replay_button = (
            f"<button type='button' class='action-btn replay-variant' data-replay-url='{replay_url.replace(sq, '&#x27;')}'>Replay API Variant</button>"
            if replay_url and is_api_replay_candidate
            else ""
        )
        anonymous_replay_button = (
            f"<button type='button' class='action-btn replay-variant' data-replay-url='{anonymous_replay_url.replace(sq, '&#x27;')}'>Replay As Anonymous</button>"
            if anonymous_replay_url and is_api_replay_candidate
            else ""
        )
        curl_button = (
            f"<button type='button' class='action-btn copy-proof-script' data-proof-script='{poc_curl.replace(sq, '&#x27;')}' data-default-label='Copy curl PoC'>Copy curl PoC</button>"
            if poc_curl
            else ""
        )
        python_button = (
            f"<button type='button' class='action-btn copy-proof-script' data-proof-script='{poc_python.replace(sq, '&#x27;')}' data-default-label='Copy Python PoC'>Copy Python PoC</button>"
            if poc_python
            else ""
        )
        detail_block = (
            observed_result_grid(item) if is_api_replay_candidate else review_summary_grid(item)
        )
        section_hint = (
            "<span class='muted'>Observed API replay result</span>"
            if is_api_replay_candidate
            else "<span class='muted'>Manual review summary</span>"
        )
        tone = (
            "bad"
            if str(item.get("severity", "")).lower() == "high"
            else "warn"
            if str(item.get("severity", "")).lower() == "medium"
            else "ok"
        )
        chain_meta = (
            f"<div class='meta'>Chain simulation: {chain_summary}</div>" if chain_summary else ""
        )
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(str(item.get('severity', 'info')))}</span>"
            f"{render_model_badge(item)} "
            f"<strong>{html.escape(item.get('title', 'Review finding'))}</strong> "
            f"<span class='muted'>confidence {html.escape(str(round(float(item.get('confidence', 0)) * 100)))}% | {html.escape(str(item.get('history_status', 'new')))}</span>"
            "</div>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>{html.escape(item.get('explanation', item.get('next_step', '')))}</span>"
            f"{chain_meta}"
            f"<div class='meta'>{section_hint}</div>"
            f"{detail_block}"
            "<div class='action-row'>"
            f"<button type='button' class='action-btn copy-review-brief' data-review-brief='{review_brief.replace(chr(39), '&#x27;')}'>Copy Review Note</button>"
            f"<button type='button' class='action-btn open-review-url' data-review-url='{review_url.replace(chr(39), '&#x27;')}'>Open URL</button>"
            f"{replay_button}"
            f"{anonymous_replay_button}"
            f"{curl_button}"
            f"{python_button}"
            "</div>"
            "</li>"
        )
    return f"<section><h2>Manual Verification Queue</h2><ul>{''.join(rows)}</ul></section>"


def verified_exploits_section(summary: dict[str, Any]) -> str:
    """Generate HTML section for verified exploit leads."""
    items = enrich_findings_with_model_severity(summary.get("verified_exploits", []))
    if not items:
        return "<section><h2>Validated Leads</h2><p class='muted'>No evidence-backed leads were promoted by the built-in validation runtime for this run.</p></section>"
    rows = []
    for item in items:
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge bad'>{html.escape(str(item.get('severity', 'info')).upper())}</span>"
            f"{render_model_badge(item)}"
            f"<strong>{html.escape(item.get('title', 'Verified result'))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}"
            f"{observed_result_grid(item)}"
            "<div class='action-row'>"
            f"<button type='button' class='action-btn open-review-url' data-review-url='{html.escape(item.get('url', ''), quote=True)}'>Open URL</button>"
            "</div>"
            "</li>"
        )
    return f"<section><h2>Validated Leads</h2><ul>{''.join(rows)}</ul></section>"


def signal_quality_section(summary: dict[str, Any]) -> str:
    """Generate HTML section summarizing signal and ML scoring metrics."""
    findings = summary.get("top_actionable_findings", [])
    signal_scored = [
        item for item in findings if item.get("signal_quality") or item.get("signal_quality_score")
    ]
    likely_true_positives = sum(
        1
        for item in findings
        if float(item.get("true_positive_probability", item.get("confidence", 0))) >= 0.8
        and item.get("endpoint_type") not in {"AUTH", "STATIC"}
    )
    likely_noise = sum(
        1
        for item in findings
        if item.get("endpoint_type") in {"AUTH", "STATIC"}
        or float(item.get("false_positive_probability", 1 - float(item.get("confidence", 0))))
        >= 0.5
    )
    multi_signal = sum(1 for item in findings if item.get("combined_signal"))
    rows = (
        f"<div class='card'><div class='label'>Likely True Positives</div><div class='value'>{likely_true_positives}</div></div>"
        f"<div class='card'><div class='label'>Likely Noise</div><div class='value'>{likely_noise}</div></div>"
        f"<div class='card'><div class='label'>Multi-Signal Flows</div><div class='value'>{multi_signal}</div></div>"
        f"<div class='card'><div class='label'>ML Quality Scored</div><div class='value'>{len(signal_scored)}</div></div>"
    )
    return f"<section><h2>Signal Quality</h2><div class='grid'>{rows}</div></section>"


def auth_bypass_findings_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    """Generate HTML section for auth bypass findings."""
    items = analysis_results.get("auth_bypass_check", [])
    if not items:
        return "<section><h2>Auth Bypass Findings</h2><p class='muted'>No authentication bypass indicators detected.</p></section>"
    rows = []
    for item in items[:20]:
        category = str(item.get("category", "auth_bypass")).replace("_", " ")
        severity = str(item.get("severity", "info")).upper()
        confidence = round(float(item.get("confidence", 0)) * 100)
        signals = item.get("signals", [])
        evidence = item.get("evidence", {})
        probe_type = evidence.get("probe_type", "unknown")
        tone = (
            "bad" if severity in ("CRITICAL", "HIGH") else "warn" if severity == "MEDIUM" else "ok"
        )
        signal_list = ", ".join(html.escape(s) for s in signals[:5]) if signals else "none"
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(severity)}</span>"
            f"<strong>{html.escape(item.get('title', 'Auth bypass finding'))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>category: {html.escape(category)} | probe: {html.escape(probe_type)} | confidence: {confidence}%</span><br>"
            f"<span class='muted'>signals: {html.escape(signal_list)}</span>"
            f"{render_mitre_badge_for_auth_bypass(item)}"
            "</li>"
        )
    return (
        f"<section><h2>Auth Bypass Findings ({len(items)})</h2><ul>{''.join(rows)}</ul></section>"
    )


def access_control_findings_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    """Generate HTML section for access control findings."""
    items = analysis_results.get("access_control_analyzer", [])
    if not items:
        return "<section><h2>Access Control Findings</h2><p class='muted'>No authorization bypass indicators detected.</p></section>"
    rows = []
    for item in items[:20]:
        severity = str(item.get("severity", "info")).upper()
        confidence = round(float(item.get("confidence", 0)) * 100)
        evidence = item.get("evidence", {})
        test_context = evidence.get("test_context", "unknown")
        result = evidence.get("result", "unknown")
        tone = (
            "bad" if severity in ("CRITICAL", "HIGH") else "warn" if severity == "MEDIUM" else "ok"
        )
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(severity)}</span>"
            f"<strong>{html.escape(item.get('title', 'Access control finding'))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>context: {html.escape(test_context)} | result: {html.escape(result)} | confidence: {confidence}%</span>"
            f"{render_mitre_badge_for_access_control(item)}"
            "</li>"
        )
    return f"<section><h2>Access Control Findings ({len(items)})</h2><ul>{''.join(rows)}</ul></section>"


def jwt_findings_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    """Generate HTML section for JWT findings."""
    items = analysis_results.get("jwt_security_analyzer", [])
    if not items:
        return "<section><h2>JWT Security Findings</h2><p class='muted'>No JWT vulnerabilities detected.</p></section>"
    rows = []
    for item in items[:20]:
        severity = str(item.get("severity", "info")).upper()
        confidence = round(float(item.get("confidence", 0)) * 100)
        signals = item.get("signals", [])
        evidence = item.get("evidence", {})
        token_preview = evidence.get("token_preview", "N/A")
        total_attacks = evidence.get("total_attacks", 0)
        vulnerable_attacks = evidence.get("vulnerable_attacks", 0)
        original_alg = evidence.get("original_algorithm", "unknown")
        attack_details = evidence.get("attack_details", [])
        tone = (
            "bad" if severity in ("CRITICAL", "HIGH") else "warn" if severity == "MEDIUM" else "ok"
        )
        signal_list = ", ".join(html.escape(s) for s in signals[:5]) if signals else "none"
        attack_type_badges = ""
        for detail in attack_details[:3]:
            finding_type = html.escape(detail.get("finding", ""))
            status_code = detail.get("status_code", "")
            attack_type_badges += (
                f"<span class='finding-badge' style='background:#e74c3c;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.8em;margin-right:4px;' "
                f"title='Status: {status_code}'>{finding_type}</span> "
            )
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(severity)}</span>"
            f"<strong>{html.escape(item.get('title', 'JWT vulnerability'))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>algorithm: {html.escape(str(original_alg))} | token: {html.escape(str(token_preview))} | confidence: {confidence}%</span><br>"
            f"<span class='muted'>attacks tested: {total_attacks} | vulnerable: {vulnerable_attacks}</span><br>"
            f"<span class='muted'>signals: {html.escape(signal_list)}</span><br>"
            f"<div style='margin-top:6px'>{attack_type_badges}</div>"
            f"{render_mitre_badges([{'technique_id': 'T1078', 'technique_name': 'Valid Accounts', 'tactic': 'Initial Access'}, {'technique_id': 'T1134', 'technique_name': 'Access Token Manipulation', 'tactic': 'Privilege Escalation'}])}"
            "</li>"
        )
    return (
        f"<section><h2>JWT Security Findings ({len(items)})</h2><ul>{''.join(rows)}</ul></section>"
    )


def tenant_isolation_findings_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    """Generate HTML section for tenant isolation findings."""
    items = analysis_results.get("tenant_isolation_check", [])
    if not items:
        return "<section><h2>Tenant Isolation Findings</h2><p class='muted'>No tenant isolation vulnerabilities detected.</p></section>"
    rows = []
    for item in items[:20]:
        severity = str(item.get("severity", "info")).upper()
        confidence = round(float(item.get("confidence", 0)) * 100)
        signals = item.get("signals", [])
        evidence = item.get("evidence", {})
        probe_type = evidence.get("probe_type", evidence.get("test_type", "unknown"))
        tenant_params = evidence.get("tenant_parameters", {})
        tone = (
            "bad" if severity in ("CRITICAL", "HIGH") else "warn" if severity == "MEDIUM" else "ok"
        )
        signal_list = ", ".join(html.escape(s) for s in signals[:5]) if signals else "none"
        tenant_param_names = ""
        if isinstance(tenant_params, dict):
            tenant_param_names = ", ".join(tenant_params.get("tenant_params", [])[:5])
        elif isinstance(tenant_params, list):
            tenant_param_names = ", ".join(str(p) for p in tenant_params[:5])
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(severity)}</span>"
            f"<strong>{html.escape(item.get('title', 'Tenant isolation finding'))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>category: tenant_isolation | probe: {html.escape(str(probe_type))} | confidence: {confidence}%</span><br>"
            f"<span class='muted'>tenant params: {html.escape(tenant_param_names) or 'inferred'}</span><br>"
            f"<span class='muted'>signals: {html.escape(signal_list)}</span>"
            f"{render_mitre_badges([{'technique_id': 'T1078', 'technique_name': 'Valid Accounts', 'tactic': 'Lateral Movement'}, {'technique_id': 'T1069', 'technique_name': 'Permission Groups Discovery', 'tactic': 'Privilege Escalation'}])}"
            "</li>"
        )
    return f"<section><h2>Tenant Isolation Findings ({len(items)})</h2><ul>{''.join(rows)}</ul></section>"


def graphql_findings_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    """Generate HTML section for GraphQL schema and introspection findings."""
    items = analysis_results.get("graphql_introspection_check", [])
    if not items:
        return "<section><h2>GraphQL Introspection &amp; Schema Findings</h2><p class='muted'>No GraphQL vulnerabilities detected.</p></section>"
    rows = []
    for item in items[:20]:
        severity = str(item.get("severity", "info")).upper()
        confidence = round(float(item.get("confidence", 0)) * 100)
        signals = item.get("signals", [])
        evidence = item.get("evidence", {})
        type_count = evidence.get("type_count", "N/A")
        query_type = evidence.get("query_type", "N/A")
        mutation_type = evidence.get("mutation_type", "N/A")
        dangerous_mutations = evidence.get("dangerous_mutations", [])
        max_depth = evidence.get("max_successful_depth", "N/A")
        batch_size = evidence.get("batch_size_accepted", "N/A")
        tone = (
            "bad" if severity in ("CRITICAL", "HIGH") else "warn" if severity == "MEDIUM" else "ok"
        )
        signal_list = ", ".join(html.escape(s) for s in signals[:5]) if signals else "none"
        mutation_badges = ""
        for m in dangerous_mutations[:5]:
            mutation_badges += (
                f"<span class='finding-badge' style='background:#e74c3c;color:#fff;padding:2px 6px;border-radius:3px;font-size:0.8em;margin-right:4px;' "
                f"title='Dangerous mutation'>{html.escape(m)}</span> "
            )
        detail_parts = []
        if type_count != "N/A":
            detail_parts.append(f"types: {type_count}")
        if query_type != "N/A":
            detail_parts.append(f"query: {query_type}")
        if mutation_type != "N/A":
            detail_parts.append(f"mutation: {mutation_type}")
        if max_depth != "N/A":
            detail_parts.append(f"max depth: {max_depth}")
        if batch_size != "N/A":
            detail_parts.append(f"batch size: {batch_size}")
        detail_text = " | ".join(detail_parts)
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(severity)}</span>"
            f"<strong>{html.escape(item.get('title', 'GraphQL vulnerability'))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>{html.escape(detail_text)} | confidence: {confidence}%</span><br>"
            f"<span class='muted'>signals: {html.escape(signal_list)}</span><br>"
            f"<div style='margin-top:6px'>{mutation_badges}</div>"
            f"{render_mitre_badges([{'technique_id': 'T1046', 'technique_name': 'Network Service Discovery', 'tactic': 'Discovery'}, {'technique_id': 'T1499', 'technique_name': 'Endpoint Denial of Service', 'tactic': 'Impact'}])}"
            "</li>"
        )
    return f"<section><h2>GraphQL Introspection &amp; Schema Findings ({len(items)})</h2><ul>{''.join(rows)}</ul></section>"
