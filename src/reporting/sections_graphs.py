"""Graph and relationship section renderers for reports.

Contains functions for rendering attack graph, endpoint relationship graph,
shared parameter tracking, auth context mapping, and finding graph sections.
Extracted from sections_general.py for better separation of concerns.
"""

from html import escape as html_escape
from typing import Any

__all__ = [
    "attack_graph_section",
    "auth_context_mapping_section",
    "endpoint_relationship_graph_section",
    "finding_graph_section",
    "shared_parameter_tracking_section",
]


def attack_graph_section(summary: dict[str, Any]) -> str:
    """Render the attack graph section."""
    graph = (
        summary.get("attack_graph", {}) if isinstance(summary.get("attack_graph", {}), dict) else {}
    )
    nodes = graph.get("nodes", []) if isinstance(graph.get("nodes", []), list) else []
    edges = graph.get("edges", []) if isinstance(graph.get("edges", []), list) else []
    chains = graph.get("chains", []) if isinstance(graph.get("chains", []), list) else []
    if not nodes and not chains:
        return "<section><h2>Attack Graph</h2><p class='muted'>No attack graph was derived.</p></section>"
    edge_type_counts: dict[str, int] = {}
    for edge in edges:
        edge_type = str(edge.get("type", "unknown"))
        edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1
    edge_summary = (
        ", ".join(f"{name}:{count}" for name, count in sorted(edge_type_counts.items())) or "none"
    )
    chain_rows = []
    for chain in chains[:10]:
        steps = chain.get("steps", []) if isinstance(chain.get("steps", []), list) else []
        if not steps:
            continue
        edge_types = " -> ".join(str(step.get("type", "edge")) for step in steps)
        endpoint_keys = ", ".join(str(value) for value in chain.get("endpoint_keys", [])[:5])
        chain_rows.append(
            "<li>"
            f"<strong>{html_escape(str(chain.get('confidence', 0)))}</strong> "
            f"<span class='muted'>{html_escape(edge_types)}</span><br>"
            f"{html_escape(endpoint_keys or 'No endpoint keys captured')}"
            "</li>"
        )
    if not chain_rows:
        chain_rows.append(
            "<li><span class='muted'>No multi-step attack chains were ranked.</span></li>"
        )
    return (
        "<section><h2>Attack Graph</h2>"
        f"<p class='muted'>nodes: {html_escape(str(len(nodes)))} | edges: {html_escape(str(len(edges)))} | chains: {html_escape(str(len(chains)))} | edge types: {html_escape(edge_summary)}</p>"
        f"<ul>{''.join(chain_rows)}</ul>"
        "</section>"
    )


def endpoint_relationship_graph_section(summary: dict[str, Any]) -> str:
    """Render the endpoint relationship graph section."""
    items = summary.get("endpoint_relationship_graph", [])
    if not items:
        return "<section><h2>Endpoint Relationship Graph</h2><p class='muted'>No cross-endpoint relationships were derived.</p></section>"
    rows = []
    for item in items[:12]:
        rows.append(
            "<li>"
            f"<strong>{html_escape(str(item.get('score', 0)))}</strong> "
            f"{html_escape(item.get('source_url', ''))} <span class='muted'>-></span> {html_escape(item.get('target_url', ''))}<br>"
            f"<span class='muted'>relationships: {html_escape(', '.join(item.get('relationship_types', [])) or 'none')}</span><br>"
            f"<span class='muted'>shared params: {html_escape(', '.join(item.get('shared_parameters', [])) or 'none')} | auth contexts: {html_escape(', '.join(item.get('shared_auth_contexts', [])) or 'none')} | flows: {html_escape(', '.join(item.get('shared_flow_labels', [])) or 'none')}</span>"
            "</li>"
        )
    return f"<section><h2>Endpoint Relationship Graph</h2><ul>{''.join(rows)}</ul></section>"


def shared_parameter_tracking_section(summary: dict[str, Any]) -> str:
    """Render the shared parameter tracking section."""
    items = summary.get("shared_parameter_tracking", [])
    if not items:
        return "<section><h2>Shared Parameter Tracking</h2><p class='muted'>No repeated parameters were clustered across endpoints.</p></section>"
    rows = []
    for item in items[:12]:
        rows.append(
            "<li>"
            f"<strong>{html_escape(item.get('parameter', 'param'))}</strong> "
            f"<span class='muted'>{html_escape(str(item.get('endpoint_count', 0)))} endpoints | {html_escape(', '.join(item.get('endpoint_types', [])) or 'unknown')}</span><br>"
            f"<span class='muted'>auth contexts: {html_escape(', '.join(item.get('auth_contexts', [])) or 'none')} | resource groups: {html_escape(', '.join(item.get('resource_groups', [])) or 'none')}</span><br>"
            f"{html_escape(', '.join(item.get('urls', [])[:4]) or 'n/a')}"
            "</li>"
        )
    return f"<section><h2>Shared Parameter Tracking</h2><ul>{''.join(rows)}</ul></section>"


def auth_context_mapping_section(summary: dict[str, Any]) -> str:
    """Render the auth context mapping section."""
    items = summary.get("auth_context_mapping", [])
    if not items:
        return "<section><h2>Auth Context Mapping</h2><p class='muted'>No auth-context map was derived.</p></section>"
    rows = []
    for item in items[:10]:
        rows.append(
            "<li>"
            f"<strong>{html_escape(item.get('context', 'context'))}</strong> "
            f"<span class='muted'>{html_escape(str(item.get('endpoint_count', 0)))} endpoints</span><br>"
            f"<span class='muted'>signals: {html_escape(', '.join(item.get('top_signals', [])) or 'none')} | resource groups: {html_escape(', '.join(item.get('resource_groups', [])) or 'none')}</span><br>"
            f"{html_escape(', '.join(item.get('urls', [])[:4]) or 'n/a')}"
            "</li>"
        )
    return f"<section><h2>Auth Context Mapping</h2><ul>{''.join(rows)}</ul></section>"


def finding_graph_section(summary: dict[str, Any]) -> str:
    """Render the finding graph section."""
    graph = (
        summary.get("finding_graph", {})
        if isinstance(summary.get("finding_graph", {}), dict)
        else {}
    )
    nodes = graph.get("nodes", []) if isinstance(graph.get("nodes", []), list) else []
    edges = graph.get("edges", []) if isinstance(graph.get("edges", []), list) else []
    if not nodes:
        return "<section><h2>Finding Graph</h2><p class='muted'>No finding graph nodes were derived.</p></section>"
    type_counts: dict[str, int] = {}
    for node in nodes:
        node_type = str(node.get("type", "unknown"))
        type_counts[node_type] = type_counts.get(node_type, 0) + 1
    calls_count = sum(1 for edge in edges if str(edge.get("type", "")) == "calls")
    depends_count = sum(1 for edge in edges if str(edge.get("type", "")) == "depends_on")
    leaks_count = sum(1 for edge in edges if str(edge.get("type", "")) == "leaks_to")
    node_summary = ", ".join(f"{key}: {value}" for key, value in sorted(type_counts.items()))
    rows = []
    for edge in edges[:14]:
        rows.append(
            "<li>"
            f"<strong>{html_escape(str(edge.get('type', 'edge')))}</strong> "
            f"{html_escape(str(edge.get('source', '')))} <span class='muted'>-></span> {html_escape(str(edge.get('target', '')))}"
            "</li>"
        )
    return (
        "<section><h2>Finding Graph</h2>"
        f"<p class='muted'>nodes: {html_escape(node_summary)} | edges: calls={calls_count}, depends_on={depends_count}, leaks_to={leaks_count}</p>"
        f"<ul>{''.join(rows)}</ul>"
        "</section>"
    )
