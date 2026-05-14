"""Advanced Attack Path Simulation Campaigns.

Turns validated findings and Threat Graph paths into multi-step
attack campaign simulations based on evidence.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "campaign_runtime.v1"


def build_attack_campaigns(
    threat_graph: dict[str, Any],
    validation_summary: dict[str, Any],
    analysis_results: dict[str, Any],
    settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build simulated attack campaigns from validated evidence.

    Args:
        threat_graph: The enriched threat graph from build_threat_graph.
        validation_summary: Summary from the validation runtime.
        analysis_results: Global analysis results for finding context.
        settings: Campaign-specific settings (max_campaigns, min_confidence, etc.).

    Returns:
        Dict conforming to campaign_runtime.v1 schema.
    """
    settings = settings or {}
    max_campaigns = int(settings.get("max_campaigns", 8))
    min_confidence = float(settings.get("min_confidence", 0.55))
    bool(settings.get("include_mitre", True))
    include_exfiltration = bool(settings.get("include_exfiltration_simulation", True))

    campaigns = []

    # 1. Identify validated entry points from the graph
    nodes = threat_graph.get("nodes", [])
    edges = threat_graph.get("edges", [])

    validated_findings = validation_summary.get("results", {})
    # results can be a dict of lists or a flat dict depending on the runtime version
    validated_ids = set()
    if isinstance(validated_findings, dict):
        for key, value in validated_findings.items():
            if isinstance(value, list):
                for item in value:
                    if item.get("status") == "ok":
                        validated_ids.add(key)
            elif isinstance(value, dict) and value.get("status") == "ok":
                validated_ids.add(key)

    if not validated_ids:
        logger.info("No validated findings found, skipping campaign generation")
        return {
            "schema_version": SCHEMA_VERSION,
            "campaigns": [],
            "summary": {"total_campaigns": 0, "max_risk": 0.0},
            "settings": settings,
        }

    # 2. Extract paths starting from validated findings
    critical_paths = threat_graph.get("critical_paths", [])
    if not critical_paths:
        from src.intelligence.graph.threat_graph import find_critical_paths
        critical_paths = find_critical_paths(threat_graph)

    for path_info in critical_paths:
        if len(campaigns) >= max_campaigns:
            break

        path = path_info.get("path", [])
        if not path:
            continue

        # Check if the entry node of this path corresponds to a validated finding
        entry_node_id = path[0]
        entry_node = next((n for n in nodes if n.get("id") == entry_node_id), {})

        finding_id = entry_node.get("finding_id", entry_node_id)
        if finding_id not in validated_ids:
            continue

        confidence = float(entry_node.get("confidence", 0.0))
        if confidence < min_confidence:
            continue

        # 3. Build campaign simulation steps
        simulated_steps = []
        path_edges = []
        tactics = set()

        for i, node_id in enumerate(path):
            node = next((n for n in nodes if n.get("id") == node_id), {})
            prev_node_id = path[i-1] if i > 0 else None

            if prev_node_id:
                edge = next((e for e in edges if e.get("source") == prev_node_id and e.get("target") == node_id), {})
                path_edges.append(edge)

            tactic = node.get("tactic") or _infer_mitre_tactic(node)
            if tactic == "Exfiltration" and not include_exfiltration:
                continue

            if tactic:
                tactics.add(tactic)

            step = {
                "step_num": i + 1,
                "action": node.get("title", "Unknown Action"),
                "node_id": node_id,
                "tactic": tactic,
                "technique": node.get("technique"),
                "evidence_required": [finding_id] if i == 0 else [f"Reachable from {prev_node_id}"],
                "stop_condition": _infer_stop_condition(node),
                "outcome": f"Simulated {node.get('role', 'step')} successful"
            }
            simulated_steps.append(step)

        # 4. Construct the campaign object
        campaign = {
            "campaign_id": str(uuid.uuid4()),
            "trigger_finding_ids": [finding_id],
            "entry_node": entry_node_id,
            "path_nodes": path,
            "path_edges": path_edges,
            "risk_score": path_info.get("risk_score", 0.0),
            "confidence": confidence,
            "mitre_sequence": [s.get("technique") for s in simulated_steps if s.get("technique")],
            "kill_chain_phase_coverage": sorted(list(tactics)),
            "simulated_steps": simulated_steps,
            "business_risk_summary": _infer_business_risk(path_nodes=[next((n for n in nodes if n.get("id") == nid), {}) for nid in path]),
        }
        campaigns.append(campaign)

    return {
        "schema_version": SCHEMA_VERSION,
        "campaigns": campaigns,
        "summary": {
            "total_campaigns": len(campaigns),
            "max_risk": max((c["risk_score"] for c in campaigns), default=0.0),
            "tactics_covered": sorted(list({t for c in campaigns for t in c["kill_chain_phase_coverage"] if t})),
        },
        "settings": settings,
    }


def _infer_mitre_tactic(node: dict[str, Any]) -> str | None:
    """Infer MITRE ATT&CK tactic from node category or role."""
    category = str(node.get("category", "")).lower()
    role = node.get("role", "")

    if "recon" in category: return "Reconnaissance"
    if "subdomain" in category: return "Reconnaissance"
    if "exploit" in category: return "Initial Access"
    if "entry" in role: return "Initial Access"
    if "ssrf" in category: return "Initial Access"
    if "lateral" in category: return "Lateral Movement"
    if "credential" in category or "key" in category: return "Credential Access"
    if "sensitive_data" in category: return "Exfiltration"
    if "impact" in role: return "Impact"

    return None


def _infer_stop_condition(node: dict[str, Any]) -> str:
    """Infer a safety stop condition for evidence-only simulation."""
    category = str(node.get("category", "")).lower()
    if "ssrf" in category: return "Stop on internal network callback"
    if "exfiltration" in category or "sensitive_data" in category: return "Stop on confirmed metadata exposure"
    if "exploit" in category: return "Stop on confirmed service response"
    return "Stop on artifact collection"


def _infer_business_risk(path_nodes: list[dict[str, Any]]) -> str:
    """Infer a human-readable business risk summary from a simulated path."""
    roles = {n.get("role") for n in path_nodes}
    categories = {str(n.get("category", "")).lower() for n in path_nodes}

    if "impact" in roles:
        if any(c in categories for c in ("sqli", "idor", "sensitive_data")):
            return "Critical: Simulated path indicates potential for unauthorized data exfiltration."
        if "ssrf" in categories:
            return "High: Simulated path indicates potential for internal network reachability and pivot."
        return "Medium: Simulated path leads to an impactful endpoint with validated entry."

    if "ssrf" in categories:
        return "High: Evidence-only simulation suggests internal reachability via SSRF."

    return "Inferred attack path from validated finding to related endpoints."
