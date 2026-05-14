import html
from typing import Any


def campaign_summary_section(summary: dict[str, Any]) -> str:
    """Render the Attack Path Simulation Campaigns section.

    Provides visibility into multi-step attack paths inferred from
    validated findings and threat graph evidence.
    """
    campaign_summary = summary.get("campaign_summary", {})
    if not campaign_summary:
        return "<section><h2>Attack Path Simulations</h2><p class='muted'>No attack campaigns simulated for this run.</p></section>"

    campaigns = campaign_summary.get("campaigns", [])
    summary_stats = campaign_summary.get("summary", {})

    if not campaigns:
        return "<section><h2>Attack Path Simulations</h2><p class='muted'>No high-confidence attack paths identified from validated evidence.</p></section>"

    parts = []
    parts.append("<section><h2>Attack Path Simulations</h2>")

    # Safety Label
    parts.append(
        "<div style='padding:10px;background:rgba(59,130,246,0.1);border-left:4px solid #3b82f6;margin-bottom:20px;'>"
        "<strong>Evidence-Only Simulation:</strong> These paths are inferred from validated findings and "
        "reachability evidence. No live lateral movement or data exfiltration was performed."
        "</div>"
    )

    # Summary Stats
    parts.append("<div class='grid'>")
    parts.append(f"<div class='card'><div class='label'>Campaign Count</div><div class='value'>{summary_stats.get('total_campaigns', 0)}</div></div>")
    parts.append(f"<div class='card'><div class='label'>Max Risk Score</div><div class='value'>{summary_stats.get('max_risk', 0.0)}</div></div>")
    parts.append(f"<div class='card'><div class='label'>MITRE Tactics</div><div class='value'>{len(summary_stats.get('tactics_covered', []))}</div></div>")
    parts.append("</div>")

    # Campaigns List
    for i, campaign in enumerate(campaigns[:5]):
        risk_score = campaign.get("risk_score", 0.0)
        risk_color = "#ef4444" if risk_score >= 0.7 else "#f59e0b" if risk_score >= 0.4 else "#6b7280"

        parts.append(
            f"<div class='campaign-card' style='border:1px solid rgba(255,255,255,0.1);border-radius:8px;padding:15px;margin-bottom:20px;'>"
            f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;'>"
            f"<h3>Campaign {i+1}: {html.escape(campaign.get('campaign_id', '')[:8])}</h3>"
            f"<span class='ui-badge' style='background:{risk_color};color:#fff;'>Risk: {risk_score}</span>"
            "</div>"
            f"<p><strong>Business Risk:</strong> {html.escape(campaign.get('business_risk_summary', 'Unknown'))}</p>"
            f"<p class='muted'><strong>Confidence:</strong> {campaign.get('confidence', 0.0)} | "
            f"<strong>Kill Chain Phases:</strong> {', '.join(campaign.get('kill_chain_phase_coverage', []))}</p>"
        )

        # Simulated Steps
        parts.append("<div style='margin-top:15px;'><strong>Simulated Steps:</strong>")
        parts.append("<ul style='list-style:none;padding-left:0;'>")
        for step in campaign.get("simulated_steps", []):
            parts.append(
                f"<li style='margin-bottom:12px;padding-left:25px;position:relative;'>"
                f"<span style='position:absolute;left:0;top:0;width:18px;height:18px;background:rgba(255,255,255,0.1);border-radius:50%;text-align:center;font-size:12px;line-height:18px;'>{step.get('step_num')}</span>"
                f"<strong>{html.escape(step.get('action', ''))}</strong>"
                f" <span class='muted' style='font-size:0.85em;'>({html.escape(step.get('tactic', 'Unknown'))})</span><br>"
                f"<span style='font-size:0.9em;'>Outcome: {html.escape(step.get('outcome', ''))}</span><br>"
                f"<span class='muted' style='font-size:0.8em;'>Evidence: {', '.join(step.get('evidence_required', []))} | "
                f"Stop condition: {html.escape(step.get('stop_condition', 'None'))}</span>"
                "</li>"
            )
        parts.append("</ul></div>")
        parts.append("</div>")

    parts.append("</section>")
    return "".join(parts)
