from src.reporting.sections_graphs import (
    attack_graph_section,
    auth_context_mapping_section,
    endpoint_relationship_graph_section,
    finding_graph_section,
    shared_parameter_tracking_section,
)
import html
import json
from typing import Any

COLLAPSE_LINE_THRESHOLD = 24
COLLAPSE_CHAR_THRESHOLD = 1200


def _render_collapsible_text(text: str, *, label: str = "details") -> str:
    line_count = max(1, text.count("\n") + 1)
    escaped_text = html.escape(text)
    if line_count < COLLAPSE_LINE_THRESHOLD and len(text) < COLLAPSE_CHAR_THRESHOLD:
        return f"<pre><code>{escaped_text}</code></pre>"
    summary = html.escape(f"Expand {label} ({line_count} lines)")
    return (
        "<details class='collapsed-block'>"
        f"<summary>{summary}</summary>"
        f"<pre><code>{escaped_text}</code></pre>"
        "</details>"
    )


def count_cards(summary: dict[str, Any]) -> str:
    return "".join(
        f"<div class='card'><div class='label'>{html.escape(label.replace('_', ' '))}</div><div class='value'>{html.escape(str(value))}</div></div>"
        for label, value in summary["counts"].items()
    )


def diff_cards(diff_summary: dict[str, Any] | None) -> str:
    if not diff_summary:
        return "<p class='muted'>No previous run available for diffing yet.</p>"
    return "".join(
        "<div class='card diff-card'>"
        f"<div class='label'>{html.escape(label.replace('_', ' '))}</div>"
        f"<div class='value'>+{info['added_count']} / -{info['removed_count']}</div>"
        f"<div class='meta'>prev {info['previous_count']} | now {info['current_count']}</div>"
        "</div>"
        for label, info in diff_summary["artifacts"].items()
    )


def list_section(title: str, items: list[str], limit: int = 30) -> str:
    if not items:
        return f"<section><h2>{html.escape(title)}</h2><p class='muted'>No data.</p></section>"
    rows = []
    for item in items[:limit]:
        text = str(item)
        if text.count("\n") >= COLLAPSE_LINE_THRESHOLD or len(text) >= COLLAPSE_CHAR_THRESHOLD:
            rows.append(f"<li>{_render_collapsible_text(text, label='text block')}</li>")
        else:
            rows.append(f"<li>{html.escape(text)}</li>")
    return f"<section><h2>{html.escape(title)}</h2><ul>{''.join(rows)}</ul></section>"


def screenshot_section(screenshots: list[dict[str, Any]]) -> str:
    successful = [shot for shot in screenshots if shot.get("file")]
    if not successful:
        return (
            "<section><h2>Screenshots</h2><p class='muted'>No screenshots captured.</p></section>"
        )
    cards = []
    for shot in successful[:24]:
        cards.append(
            "<div class='shot'>"
            f"<a href='{html.escape(shot['file'])}' target='_blank' rel='noreferrer'>"
            f"<img src='{html.escape(shot['file'])}' alt='{html.escape(shot['url'])}'></a>"
            f"<div class='shot-url'>{html.escape(shot['url'])}</div></div>"
        )
    return f"<section><h2>Screenshots</h2><div class='shots'>{''.join(cards)}</div></section>"


def analysis_section(title: str, items: list[dict[str, Any]], limit: int = 20) -> str:
    if not items:
        return f"<section><h2>{html.escape(title)}</h2><p class='muted'>No findings.</p></section>"
    rows = []
    for item in items[:limit]:
        pretty = json.dumps(item, ensure_ascii=False, indent=2)
        rows.append(f"<li>{_render_collapsible_text(pretty, label='finding payload')}</li>")
    return f"<section><h2>{html.escape(title)}</h2><ul>{''.join(rows)}</ul></section>"


def high_value_section(items: list[dict[str, Any]]) -> str:
    if not items:
        return "<section><h2>High-Value Endpoints</h2><p class='muted'>No scored endpoints.</p></section>"
    rows = []
    for item in items[:20]:
        label = html.escape(item.get("url", ""))
        score = item.get("score", 0)
        suffix = " with params" if item.get("has_parameters") else ""
        rows.append(f"<li><strong>{score}</strong> {label}{suffix}</li>")
    return f"<section><h2>High-Value Endpoints</h2><ul>{''.join(rows)}</ul></section>"


def prioritized_endpoints_section(summary: dict[str, Any]) -> str:
    items = summary.get("prioritized_endpoints", [])
    if not items:
        return "<section><h2>Multi-Signal Prioritized Endpoints</h2><p class='muted'>No enriched endpoint ranking available yet.</p></section>"
    rows = []
    for item in items[:10]:
        hints = " | ".join(item.get("attack_hints", [])[:2]) or "No hint generated."
        payloads = ", ".join(
            f"{entry.get('parameter')}={entry.get('variant')}"
            for entry in item.get("payload_suggestions", [])[:3]
        )
        rows.append(
            "<li>"
            f"<strong>{html.escape(str(item.get('score', 0)))}</strong> {html.escape(item.get('url', ''))}<br>"
            f"<span class='muted'>signals: {html.escape(', '.join(item.get('signals', [])) or 'none')} | multi-signal: {html.escape(', '.join(item.get('multi_signal_priority', [])) or 'none')}</span><br>"
            f"<span class='muted'>decision: {html.escape(str(item.get('decision', 'MEDIUM')))} | attack chain score: {html.escape(str(item.get('attack_chain_score', 0)))}</span><br>"
            f"<span class='muted'>hint: {html.escape(hints)}</span><br>"
            f"<span class='muted'>payload ideas: {html.escape(payloads or 'none')}</span>"
            "</li>"
        )
    return f"<section><h2>Multi-Signal Prioritized Endpoints</h2><ul>{''.join(rows)}</ul></section>"




def flow_detection_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    items = analysis_results.get("flow_detector", [])
    if not items:
        return "<section><h2>Flow Detection</h2><p class='muted'>No multi-step auth or redirect chains detected.</p></section>"
    rows = [
        "<li>"
        f"<strong>{html.escape(item.get('label', 'flow'))}</strong> "
        f"<span class='muted'>{html.escape(item.get('host', ''))}</span><br>"
        f"{html.escape(' -> '.join(item.get('chain', [])))}"
        "</li>"
        for item in items[:8]
    ]
    return f"<section><h2>Flow Detection</h2><ul>{''.join(rows)}</ul></section>"


def response_diff_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    items = analysis_results.get("response_diff_engine", [])
    if not items:
        return "<section><h2>Response Diff Highlights</h2><p class='muted'>No response diffs were generated.</p></section>"
    rows = [
        "<li>"
        f"<strong>{html.escape(item.get('parameter', 'param'))}</strong> on {html.escape(item.get('url', ''))}<br>"
        f"<span class='muted'>status {html.escape(str(item.get('original_status')))} -> {html.escape(str(item.get('mutated_status')))} | redirect changed: {html.escape(str(item.get('redirect_changed')))} | content changed: {html.escape(str(item.get('content_changed')))} | similarity {html.escape(str(item.get('body_similarity')))}</span>"
        "</li>"
        for item in items[:12]
    ]
    return f"<section><h2>Response Diff Highlights</h2><ul>{''.join(rows)}</ul></section>"


def behavior_analysis_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    items = analysis_results.get("behavior_analysis_layer", [])
    if not items:
        return "<section><h2>Behavior Analysis</h2><p class='muted'>No controlled variant behavior results were captured.</p></section>"
    rows = []
    for item in items[:12]:
        diff = item.get("diff", {})
        flow = item.get("flow_transition", {})
        tone = (
            "bad"
            if item.get("confirmed") or item.get("impact_level") == "high"
            else "warn"
            if item.get("impact_level") == "medium"
            else "ok"
        )
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{html.escape(str(item.get('impact_level', 'low')))}</span>"
            f"<strong>{html.escape(item.get('parameter', 'param'))}={html.escape(item.get('variant', ''))}</strong>"
            "</div>"
            f"{html.escape(item.get('url', ''))}"
            "<div class='finding-grid'>"
            f"<div class='finding-metric'><strong>Stability</strong>{html.escape(str(item.get('stability', 'candidate')))}</div>"
            f"<div class='finding-metric'><strong>Similarity</strong>{html.escape(str(diff.get('body_similarity')))}</div>"
            f"<div class='finding-metric'><strong>Flow</strong>{html.escape(str(flow.get('from', '')))} -> {html.escape(str(flow.get('to', '')))}</div>"
            f"<div class='finding-metric'><strong>Boundary Shift</strong>{html.escape(str(item.get('trust_boundary_shift', False)))}</div>"
            "</div>"
            f"<p class='meta'>Status changed {html.escape(str(diff.get('status_changed')))} | redirect changed {html.escape(str(diff.get('redirect_changed')))} | content changed {html.escape(str(diff.get('content_changed')))}</p>"
            "</li>"
        )
    return f"<section><h2>Behavior Analysis</h2><ul>{''.join(rows)}</ul></section>"


def response_snapshot_section(analysis_results: dict[str, list[dict[str, Any]]]) -> str:
    items = analysis_results.get("response_snapshot_system", [])
    if not items:
        return "<section><h2>Response Snapshots</h2><p class='muted'>No baseline snapshots captured.</p></section>"
    rows = [
        "<li>"
        f"{html.escape(item.get('url', ''))}<br>"
        f"<span class='muted'>status {html.escape(str(item.get('status_code')))} | length {html.escape(str(item.get('response_length')))} | patterns {html.escape(', '.join(item.get('key_patterns', [])) or 'none')}</span>"
        "</li>"
        for item in items[:12]
    ]
    return f"<section><h2>Response Snapshots</h2><ul>{''.join(rows)}</ul></section>"


def stat_grid_section(title: str, items: dict[str, Any], empty_message: str) -> str:
    if not items:
        return f"<section><h2>{html.escape(title)}</h2><p class='muted'>{html.escape(empty_message)}</p></section>"
    rows = "".join(
        f"<div class='card'><div class='label'>{html.escape(label.replace('_', ' '))}</div><div class='value'>{html.escape(str(value))}</div></div>"
        for label, value in items.items()
    )
    return f"<section><h2>{html.escape(title)}</h2><div class='grid'>{rows}</div></section>"


def module_metrics_section(summary: dict[str, Any]) -> str:
    module_metrics = summary.get("module_metrics", {})
    if not module_metrics:
        return "<section><h2>Module Status</h2><p class='muted'>No module metrics available.</p></section>"
    rows = []
    for label, info in module_metrics.items():
        if isinstance(info, dict):
            status = info.get("status", "unknown")
            duration = info.get("duration_seconds", 0)
        elif isinstance(info, list):
            status = "ok"
            duration = 0
        else:
            status = "unknown"
            duration = 0
        rows.append(
            "<li>"
            f"<strong>{html.escape(label.replace('_', ' '))}</strong>: "
            f"status={html.escape(str(status))} "
            f"duration={html.escape(str(duration))}s"
            "</li>"
        )
    return f"<section><h2>Module Status</h2><ul>{''.join(rows)}</ul></section>"


def next_steps_section(summary: dict[str, Any]) -> str:
    steps = summary.get("next_steps", [])
    if not steps:
        return (
            "<section><h2>Next Step Suggestions</h2><p class='muted'>No suggestions.</p></section>"
        )
    rows = "".join(f"<li>{html.escape(step)}</li>" for step in steps)
    return f"<section><h2>Next Step Suggestions</h2><ul>{rows}</ul></section>"


def detection_gap_section(
    summary: dict[str, Any], analysis_results: dict[str, Any] | None = None
) -> str:
    """Render a detection gap analysis showing coverage and potential blind spots.

    Highlights which vulnerability categories were tested, which had findings,
    and which modules produced no results (potential gaps).
    """
    detection_coverage = summary.get("detection_coverage", {})
    if not detection_coverage:
        return ""

    empty = detection_coverage.get("empty_modules", [])
    coverage_score = detection_coverage.get("coverage_score", 0)
    category_counts = detection_coverage.get("coverage_by_category", {})
    signal_dist = detection_coverage.get("signal_distribution", {})

    # Known vulnerability categories that should be tested
    expected_categories = {
        "idor",
        "ssrf",
        "open_redirect",
        "token_leak",
        "xss",
        "access_control",
        "business_logic",
        "authentication_bypass",
        "broken_authentication",
        "session",
        "payment",
        "server_side_injection",
        "misconfiguration",
        "exposure",
        "anomaly",
        "redirect",
        "race_condition",
        "ai_surface",
    }
    covered_categories = set(category_counts.keys())
    gap_categories = expected_categories - covered_categories

    parts: list[str] = []
    parts.append("<section><h2>Detection Coverage Analysis</h2>")

    # Coverage score
    score_color = (
        "#22c55e" if coverage_score >= 0.7 else "#f59e0b" if coverage_score >= 0.4 else "#ef4444"
    )
    parts.append(
        "<div style='padding:12px;background:rgba(255,255,255,0.03);border-radius:8px;margin-bottom:16px'>"
    )
    finding_modules = detection_coverage.get(
        "modules_with_findings_count",
        detection_coverage.get("active_count", 0),
    )
    total_modules = detection_coverage.get("total_modules", 0)

    parts.append(
        f"<strong>Detection Yield:</strong> <span style='color:{score_color};font-weight:bold'>{coverage_score:.0%}</span>"
    )
    parts.append(f" ({finding_modules}/{total_modules} modules produced findings)")
    parts.append(
        "<div class='muted' style='margin-top:6px'>"
        "This metric reflects finding-producing modules, not total modules evaluated."
        "</div>"
    )
    parts.append("</div>")

    # Category coverage
    if category_counts:
        parts.append("<h3>Findings by Category</h3><ul>")
        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1])[:15]:
            parts.append(f"<li><strong>{html.escape(cat)}</strong>: {count} findings</li>")
        parts.append("</ul>")

    # Signal distribution
    if signal_dist:
        parts.append("<h3>Top Signals</h3><ul>")
        for sig, count in list(signal_dist.items())[:10]:
            parts.append(f"<li><code>{html.escape(sig)}</code>: {count} occurrences</li>")
        parts.append("</ul>")

    # Gap analysis
    if gap_categories:
        parts.append(f"<h3>Potential Gaps ({len(gap_categories)} categories without findings)</h3>")
        parts.append("<ul>")
        for cat in sorted(gap_categories):
            parts.append(
                f"<li class='muted'>{html.escape(cat)} — no findings detected; consider targeted testing</li>"
            )
        parts.append("</ul>")

    # Empty modules
    if empty:
        parts.append(f"<h3>Inactive Modules ({len(empty)})</h3>")
        parts.append("<ul>")
        for mod in sorted(empty)[:10]:
            parts.append(f"<li class='muted'>{html.escape(mod)}</li>")
        parts.append("</ul>")

    parts.append("</section>")
    return "".join(parts)


def technology_section(summary: dict[str, Any]) -> str:
    technologies = summary.get("technology_summary", [])
    if not technologies:
        return "<section><h2>Technology Fingerprints</h2><p class='muted'>No strong technology indicators detected.</p></section>"
    rows = "".join(
        f"<li><strong>{html.escape(item.get('technology', 'unknown'))}</strong> <span class='muted'>{item.get('count', 0)} hits</span></li>"
        for item in technologies
    )
    return f"<section><h2>Technology Fingerprints</h2><ul>{rows}</ul></section>"


def vrt_coverage_section(summary: dict[str, Any]) -> str:
    coverage = summary.get("vrt_coverage", {})
    entries = coverage.get("entries", [])
    if not entries:
        return "<section><h2>P1 VRT Coverage</h2><p class='muted'>No coverage matrix available.</p></section>"
    stats = coverage.get("summary", {})
    stat_rows = "".join(
        f"<div class='card'><div class='label'>{html.escape(label.replace('_', ' '))}</div><div class='value'>{html.escape(str(value))}</div></div>"
        for label, value in stats.items()
    )
    entry_rows = []
    for item in entries:
        active_checks = ", ".join(item.get("active_checks", [])[:6]) or "none"
        variant = str(item.get("variant", "")).strip()
        entry_rows.append(
            "<li>"
            f"<strong>{html.escape(item.get('status', 'unsupported').replace('_', ' '))}</strong> "
            f"{html.escape(item.get('vrt_category', ''))} / {html.escape(item.get('vulnerability_name', ''))}"
            f"{' / ' + html.escape(variant) if variant else ''}<br>"
            f"<span class='muted'>active checks: {html.escape(active_checks)}</span><br>"
            f"<span class='muted'>{html.escape(item.get('notes', ''))}</span>"
            "</li>"
        )
    return f"<section><h2>P1 VRT Coverage</h2><div class='grid'>{stat_rows}</div><ul>{''.join(entry_rows)}</ul></section>"


def validation_plan_section(summary: dict[str, Any]) -> str:
    plans = summary.get("validation_plans", [])
    if not plans:
        return "<section><h2>Validation Plan</h2><p class='muted'>No validation plans generated yet.</p></section>"
    rows = []
    for plan in plans[:30]:
        target = html.escape(str(plan.get("target", "")))
        method = html.escape(str(plan.get("method", "GET")))
        desc = html.escape(str(plan.get("description", "")))
        risk = html.escape(str(plan.get("risk_level", "unknown")))
        rows.append(
            "<li>"
            f"<strong>{method}</strong> {target}<br>"
            f"<span class='muted'>risk: {risk} | {desc}</span>"
            "</li>"
        )
    return f"<section><h2>Validation Plan ({len(plans)} targets)</h2><ul>{''.join(rows)}</ul></section>"


def cloud_metadata_section(items: list[dict[str, Any]]) -> str:
    if not items:
        return "<section><h2>Cloud Metadata &amp; Infrastructure Exposure</h2><p class='muted'>No cloud metadata or infrastructure exposure findings.</p></section>"
    rows = []
    for item in items[:30]:
        title = html.escape(str(item.get("title", "")))
        url = html.escape(str(item.get("url", "")))
        severity = html.escape(str(item.get("severity", "unknown")))
        category = html.escape(str(item.get("category", "")))
        signals = ", ".join(item.get("signals", [])[:5]) or "none"
        evidence = item.get("evidence", {})
        raw_preview = (
            evidence.get("matched_tokens")
            or evidence.get("cloud_headers")
            or evidence.get("service_hint")
            or evidence.get("path_token")
            or "see details"
        )
        evidence_preview = html.escape(str(raw_preview))[:120]
        tone = (
            "bad" if severity in ("critical", "high") else "warn" if severity == "medium" else "ok"
        )
        rows.append(
            "<li class='finding-card'>"
            "<div class='finding-head'>"
            f"<span class='ui-badge {tone}'>{severity}</span>"
            f"<strong>{title}</strong>"
            "</div>"
            f"<span class='muted'>{url}</span><br>"
            f"<span class='muted'>category: {category} | evidence: {evidence_preview}</span><br>"
            f"<span class='muted'>signals: {html.escape(signals)}</span>"
            "</li>"
        )
    return f"<section><h2>Cloud Metadata &amp; Infrastructure Exposure ({len(items)} findings)</h2><ul>{''.join(rows)}</ul></section>"


def risk_score_section(risk_data: dict[str, Any]) -> str:
    """Render aggregate risk score widget.

    Args:
        risk_data: Dict from compute_aggregate_risk_score.

    Returns:
        HTML section string.
    """
    if not risk_data or not risk_data.get("finding_count"):
        return "<section><h2>Target Risk Score</h2><p class='muted'>No findings to calculate risk score.</p></section>"

    score = risk_data.get("aggregate_score", 0)
    label = risk_data.get("score_label", "info")
    max_sev = risk_data.get("max_severity", "info")
    avg = risk_data.get("average_score", 0)
    severity_breakdown = risk_data.get("severity_breakdown", {})
    category_scores = risk_data.get("category_scores", {})

    color_map = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#f59e0b",
        "low": "#22c55e",
        "info": "#6b7280",
    }
    score_color = color_map.get(label, "#6b7280")

    parts: list[str] = []
    parts.append("<section><h2>Target Risk Score</h2>")
    parts.append(
        "<div style='padding:16px;background:rgba(255,255,255,0.03);border-radius:8px;margin-bottom:16px;"
        f"border-left:4px solid {score_color}'>"
    )
    parts.append(f"<div style='font-size:2em;font-weight:bold;color:{score_color}'>{score}</div>")
    parts.append(
        f"<div style='color:{score_color};font-weight:600;text-transform:uppercase'>{html.escape(label)} risk</div>"
    )
    parts.append(
        f"<div class='muted'>Max severity: {html.escape(max_sev)} | Avg score: {avg}</div>"
    )
    parts.append("</div>")

    if severity_breakdown:
        parts.append("<h3>Severity Breakdown</h3><ul>")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_breakdown.get(sev, 0)
            if count > 0:
                sev_color = color_map.get(sev, "#6b7280")
                parts.append(
                    f"<li><span style='color:{sev_color};font-weight:bold'>{html.escape(sev)}</span>: {count}</li>"
                )
        parts.append("</ul>")

    if category_scores:
        parts.append("<h3>Risk by Category</h3><ul>")
        for cat, cat_score in list(category_scores.items())[:10]:
            parts.append(f"<li><strong>{html.escape(cat)}</strong>: {cat_score}</li>")
        parts.append("</ul>")

    parts.append("</section>")
    return "".join(parts)


def analyst_notes_section(notes: list[dict[str, Any]]) -> str:
    """Render analyst notes section for reports.

    Args:
        notes: List of note dicts from get_all_notes.

    Returns:
        HTML section string.
    """
    if not notes:
        return "<section><h2>Analyst Notes</h2><p class='muted'>No analyst notes recorded.</p></section>"

    parts: list[str] = []
    parts.append("<section><h2>Analyst Notes</h2>")

    for note in notes:
        note_text = html.escape(str(note.get("note", "")))
        finding_id = html.escape(str(note.get("finding_id", "")))
        author = html.escape(str(note.get("author", "anonymous")))
        created = html.escape(str(note.get("created_at", "")))
        tags = note.get("tags", [])
        tags_html = ""
        if tags:
            tag_spans = " ".join(
                f"<span class='ui-badge' style='background:rgba(99,102,241,0.2);color:#818cf8'>{html.escape(str(t))}</span>"
                for t in tags
            )
            tags_html = f"<div style='margin-top:4px'>{tag_spans}</div>"

        parts.append(
            "<div style='padding:12px;background:rgba(255,255,255,0.03);border-radius:6px;margin-bottom:8px'>"
            f"<div class='muted'>finding: {finding_id} | by {author} | {created}</div>"
            f"<p>{note_text}</p>"
            f"{tags_html}"
            "</div>"
        )

    parts.append("</section>")
    return "".join(parts)


__all__ = [
    "analysis_section",
    "analyst_notes_section",
    "attack_graph_section",
    "auth_context_mapping_section",
    "behavior_analysis_section",
    "cloud_metadata_section",
    "count_cards",
    "detection_gap_section",
    "diff_cards",
    "endpoint_relationship_graph_section",
    "finding_graph_section",
    "flow_detection_section",
    "high_value_section",
    "list_section",
    "module_metrics_section",
    "next_steps_section",
    "prioritized_endpoints_section",
    "response_diff_section",
    "response_snapshot_section",
    "risk_score_section",
    "screenshot_section",
    "shared_parameter_tracking_section",
    "stat_grid_section",
    "technology_section",
    "validation_plan_section",
    "vrt_coverage_section",
]
