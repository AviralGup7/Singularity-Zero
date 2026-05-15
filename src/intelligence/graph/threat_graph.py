"""Threat graph operations combining findings, endpoints, and intel.

Provides functions for building comprehensive threat graphs,
identifying critical attack paths, and computing risk summaries.
"""

from typing import Any, cast


def build_threat_graph(
    findings: list[dict],
    endpoints: list[dict] | None = None,
    include_cves: bool = True,
    include_mitre: bool = True,
) -> dict:
    """Build a comprehensive threat graph combining findings, endpoints, and intel.

    Args:
        findings: List of finding dicts with category, severity, url, etc.
        endpoints: Optional list of endpoint dicts for context.
        include_cves: Whether to include CVE references in the graph.
        include_mitre: Whether to include MITRE ATT&CK techniques.

    Returns:
        Dict with nodes, edges, critical_paths, and risk_summary.
    """
    from src.analysis.intelligence.endpoint_attack_graph import build_attack_graph

    # FIXME: endpoints is a list but build_attack_graph expects a dict for analysis_results.
    # Casting to Any for now to maintain existing behavior.
    graph = cast(dict[str, Any], build_attack_graph(findings, cast(Any, endpoints or [])))

    # Enrich with threat intelligence markers
    cve_count = 0
    mitre_count = 0
    for node in graph.get("nodes", []):
        if include_cves and "threat_intel" in node:
            cves = node["threat_intel"].get("cves", [])
            cve_count += len(cves)
            node["cve_references"] = cves
        if include_mitre and "threat_intel" in node:
            mitre = node["threat_intel"].get("mitre", [])
            mitre_count += len(mitre)
            node["mitre_techniques"] = mitre

    graph["intel_enrichment"] = {
        "cve_references": cve_count,
        "mitre_techniques": mitre_count,
    }

    return graph


def find_critical_paths(graph: dict, min_severity: str = "high") -> list[dict]:
    """Identify critical attack paths in the threat graph.

    Finds paths where all nodes meet the minimum severity threshold
    and represent a complete attack chain from entry to impact.

    Args:
        graph: Threat graph dict with nodes and edges.
        min_severity: Minimum severity to include (low, medium, high, critical).

    Returns:
        List of critical path dicts with nodes, risk_score, and description.
    """
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_score = severity_order.get(min_severity, 3)

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    # Build adjacency list
    adjacency: dict[str, list[str]] = {}
    node_map: dict[str, dict] = {}
    for node in nodes:
        node_id = node.get("id", "")
        node_map[node_id] = node
        adjacency.setdefault(node_id, [])

    for edge in edges:
        src = edge.get("source", "")
        dst = edge.get("target", "")
        adjacency.setdefault(src, []).append(dst)

    # Find paths from entry points to impact nodes
    entry_nodes = [n for n in nodes if n.get("role") == "entry"]
    impact_nodes = {n.get("id") for n in nodes if n.get("role") == "impact"}

    critical_paths: list[dict] = []
    for entry in entry_nodes:
        entry_id = entry.get("id", "")
        visited: set[str] = set()
        stack = [(entry_id, [entry_id])]

        while stack:
            current, path = stack.pop()
            if current in visited:
                continue
            visited.add(current)

            if current in impact_nodes and len(path) >= 2:
                path_nodes = [node_map.get(nid, {}) for nid in path]
                severities = [severity_order.get(n.get("severity", "low"), 0) for n in path_nodes]
                if all(s >= min_score for s in severities):
                    risk = sum(s for s in severities) / max(1, len(severities))
                    critical_paths.append(
                        {
                            "path": path,
                            "risk_score": round(risk / 4.0, 2),
                            "description": " -> ".join(
                                node_map.get(nid, {}).get("title", nid) for nid in path
                            ),
                            "length": len(path),
                        }
                    )

            for neighbor in adjacency.get(current, []):
                if neighbor not in visited:
                    stack.append((neighbor, path + [neighbor]))

    critical_paths.sort(key=lambda p: p["risk_score"], reverse=True)
    return critical_paths


def annotate_graph_for_campaigns(graph: dict, validation_results: dict) -> dict:
    """Annotate the threat graph with campaign-specific markers.

    Marks validated entry points, sensitive-data nodes, SSRF-reachability
    edges, and potential lateral-movement paths.

    Args:
        graph: Threat graph dict.
        validation_results: Results from the validation runtime.

    Returns:
        Updated threat graph dict.
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    # results can be a dict of lists or a flat dict depending on the runtime version
    validated_ids = set()
    if isinstance(validation_results, dict):
        for key, value in validation_results.items():
            if isinstance(value, list):
                for item in value:
                    if item.get("status") == "ok":
                        validated_ids.add(key)
            elif isinstance(value, dict) and value.get("status") == "ok":
                validated_ids.add(key)

    # 1. Annotate nodes
    for node in nodes:
        node_id = node.get("id")
        category = str(node.get("category", "")).lower()

        # Mark validated nodes
        if node_id in validated_ids:
            node["validated"] = True
            node["campaign_role"] = "validated_entry"

        # Mark sensitive data nodes
        if any(c in category for c in ("credential", "key", "secret", "token", "pii", "user_data")):
            node["sensitive_data"] = True
            node["role"] = "impact"

        # Refine roles based on categories
        if "ssrf" in category:
            node["campaign_role"] = "pivot_point"

    # 2. Annotate edges
    for edge in edges:
        source_id = edge.get("source")
        target_id = edge.get("target")
        source_node: dict[str, Any] = next((n for n in nodes if n.get("id") == source_id), {})
        target_node: dict[str, Any] = next((n for n in nodes if n.get("id") == target_id), {})

        # Mark SSRF internal reachability
        if "ssrf" in str(source_node.get("category", "")).lower():
            edge["type"] = "internal_reachability"
            edge["campaign_label"] = "SSRF Pivot"

        # Infer lateral movement if connecting different host contexts
        source_host = source_node.get("host")
        target_host = target_node.get("host")
        if source_host and target_host and source_host != target_host:
            edge["type"] = "lateral_movement"
            edge["campaign_label"] = "Lateral Pivot"

    return graph


def graph_risk_summary(graph: dict) -> dict:
    """Compute a risk summary from the threat graph.

    Args:
        graph: Threat graph dict with nodes and edges.

    Returns:
        Dict with total_nodes, total_edges, severity_distribution,
        attack_chain_count, overall_risk_score, and top_tactics.
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    severity_dist: dict[str, int] = {}
    tactics: dict[str, int] = {}
    risk_scores: list[float] = []

    for node in nodes:
        sev = node.get("severity", "unknown")
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

        risk = node.get("risk_score", 0.0)
        if isinstance(risk, (int, float)):
            risk_scores.append(float(risk))

        for tactic in node.get("mitre_techniques", []):
            tactic_name = tactic.get("tactic", "unknown")
            tactics[tactic_name] = tactics.get(tactic_name, 0) + 1

    overall_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

    # Count attack chains (connected components with 3+ nodes)
    adjacency: dict[str, set[str]] = {}
    all_ids: set[str] = set()
    for node in nodes:
        nid = node.get("id", "")
        all_ids.add(nid)
        adjacency.setdefault(nid, set())

    for edge in edges:
        src = edge.get("source", "")
        dst = edge.get("target", "")
        adjacency.setdefault(src, set()).add(dst)
        adjacency.setdefault(dst, set()).add(src)

    visited: set[str] = set()
    chain_count = 0
    for nid in all_ids:
        if nid in visited:
            continue
        component: set[str] = set()
        stack = [nid]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            component.add(current)
            for neighbor in adjacency.get(current, set()):
                if neighbor not in visited:
                    stack.append(neighbor)
        if len(component) >= 3:
            chain_count += 1

    top_tactics = sorted(tactics.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "severity_distribution": severity_dist,
        "attack_chain_count": chain_count,
        "overall_risk_score": round(overall_risk, 2),
        "top_tactics": [{"tactic": t, "count": c} for t, c in top_tactics],
    }
