"""Endpoint intelligence module.

Builds comprehensive endpoint intelligence profiles by aggregating
signals from all analysis modules, applying scoring and confidence
calculation, and generating attack graphs and relationship maps.

This package modularizes the endpoint intelligence logic into separate files
for better maintainability and AI-agent editability.
"""

from typing import Any

from src.analysis.helpers import (
    endpoint_base_key,
    endpoint_signature,
    is_auth_flow_endpoint,
    meaningful_query_pairs,
)
from src.analysis.intelligence.endpoint_attack_graph import build_attack_graph
from src.analysis.intelligence.endpoint_graphs import (
    build_auth_context_mapping,
    build_endpoint_relationship_graph,
    build_finding_graph,
    build_shared_parameter_tracking,
)

from ._scoring import enrich_and_score_endpoints
from ._signal_collection import collect_module_signals

__all__ = [
    "build_endpoint_intelligence",
    "build_attack_graph",
    "build_auth_context_mapping",
    "build_endpoint_relationship_graph",
    "build_finding_graph",
    "build_shared_parameter_tracking",
]


from src.core.plugins import register_plugin

ENRICHMENT_PROVIDER = "enrichment_provider"


@register_plugin(ENRICHMENT_PROVIDER, "endpoint_intelligence")
def build_endpoint_intelligence(
    ranked_priority_urls: list[dict[str, Any]],
    analysis_results: dict[str, list[dict[str, Any]]],
    validation_summary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build comprehensive endpoint intelligence profiles.

    Aggregates signals from all analysis modules, applies scoring and
    confidence calculation, generates attack graphs, and returns
    enriched endpoint profiles sorted by priority.

    Args:
        ranked_priority_urls: Pre-ranked URLs with scores.
        analysis_results: Results from all analysis modules.
        validation_summary: Optional validation results.

    Returns:
        List of enriched endpoint intelligence profiles (max 30).
    """
    endpoint_map: dict[str, dict[str, Any]] = {}
    _url_cache: dict[str, dict[str, Any]] = {}
    validation_results = (
        validation_summary.get("results", {}) if isinstance(validation_summary, dict) else {}
    )

    # Initialize endpoint records from priority URLs
    for item in ranked_priority_urls:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        key = endpoint_signature(url)
        if key in endpoint_map:
            record = endpoint_map[key]
        else:
            if url not in _url_cache:
                _url_cache[url] = {
                    "endpoint_base_key": endpoint_base_key(url),
                    "is_auth_flow": is_auth_flow_endpoint(url),
                    "query_parameters": {key for key, _ in meaningful_query_pairs(url)},
                }
            cached = _url_cache[url]
            record = {
                "url": url,
                "endpoint_key": key,
                "endpoint_base_key": cached["endpoint_base_key"],
                "endpoint_type": "AUTH" if cached["is_auth_flow"] else "GENERAL",
                "base_score": 0,
                "normalized_score": 0.0,
                "signals": set(),
                "evidence_modules": set(),
                "signal_cooccurrence": {},
                "flow_labels": set(),
                "attack_hints": [],
                "payload_suggestions": [],
                "response_diff": None,
                "response_snapshot": None,
                "parameter_sensitivity": 0,
                "trust_boundary": "same-host",
                "flow_score": 0,
                "evidence_confidence": 0.42,
                "resource_group": "",
                "schema_markers": [],
                "query_parameters": cached["query_parameters"],
                "auth_contexts": set(),
            }
            endpoint_map[key] = record

        record["base_score"] = max(record["base_score"], int(item.get("score", 0)))
        record["normalized_score"] = max(
            record["normalized_score"], float(item.get("normalized_score", 0))
        )
        record["flow_score"] = max(record["flow_score"], int(item.get("flow_score", 0)))
        record["endpoint_type"] = str(item.get("endpoint_type") or record["endpoint_type"])
        record["parameter_sensitivity"] = max(
            record["parameter_sensitivity"], int(item.get("parameter_sensitivity", 0))
        )
        if item.get("trust_boundary") and record["trust_boundary"] != "cross-host":
            record["trust_boundary"] = str(item.get("trust_boundary"))
        if is_auth_flow_endpoint(url):
            record["signals"].add("auth")
            record["auth_contexts"].add("auth_flow")

    # Collect signals from all modules
    collect_module_signals(endpoint_map, analysis_results, validation_summary)

    # Enrich and score
    enriched = enrich_and_score_endpoints(endpoint_map, validation_results)

    # Build attack graph
    attack_graph_raw = build_attack_graph(enriched, analysis_results)
    endpoint_nodes_raw = attack_graph_raw.get("endpoint_nodes", {})
    endpoint_nodes: dict[str, list[str]] = {}
    if isinstance(endpoint_nodes_raw, dict):
        for key, values in endpoint_nodes_raw.items():
            if isinstance(values, list):
                endpoint_nodes[str(key)] = [str(v) for v in values]

    endpoint_chain_score: dict[str, float] = {}
    chains_raw = attack_graph_raw.get("chains", [])
    if isinstance(chains_raw, list):
        for chain in chains_raw:
            chain_score = float(chain.get("confidence", 0.0) or 0.0)
            for endpoint_key in chain.get("endpoint_keys", []):
                normalized_key = str(endpoint_key).strip()
                if not normalized_key:
                    continue
                endpoint_chain_score[normalized_key] = max(
                    endpoint_chain_score.get(normalized_key, 0.0), chain_score
                )

    for item in enriched:
        endpoint_key = str(item.get("endpoint_key", "")).strip()
        item["attack_graph_nodes"] = endpoint_nodes.get(endpoint_key, [])[:4]
        item["attack_chain_score"] = round(endpoint_chain_score.get(endpoint_key, 0.0), 3)

    # Sort and apply cross-endpoint correlation
    enriched.sort(
        key=lambda item: (
            item["decision"] != "HIGH",
            -item["signal_count"],
            -item.get("score", 0),
            item["url"],
        )
    )
    from src.analysis.intelligence.endpoint_scoring import _apply_cross_endpoint_correlation

    _apply_cross_endpoint_correlation(enriched)

    return enriched[:30]
