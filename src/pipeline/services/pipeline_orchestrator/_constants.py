"""Constants and configuration for pipeline orchestration.

The Neural-Mesh executable graph lives in ``STAGE_GRAPH`` and is the
single source of truth for dependencies, conditional gating, and
priority weights.  The legacy ``STAGE_DEPS`` mapping is now derived
from the graph for backward compatibility with dashboards and
plugins; new code should import ``STAGE_GRAPH`` directly.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ._graph_dsl import Graph
from .graph_builder import build_pipeline_graph, _load_capability_profile
from src.pipeline.stage_registry import _global_stage_registry

__all__ = [
    "PIPELINE_STAGES",
    "STAGE_ORDER",
    "STAGE_TIMEOUTS",
    "STAGE_DEPS",
    "STAGE_GRAPH",
    "DEFAULT_ITERATION_LIMIT",
    "DEFAULT_TIMEOUT_SECONDS",
]


logger = logging.getLogger(__name__)


PIPELINE_STAGES = {
    "subdomains": "Subdomain enumeration",
    "subdomain_takeover": "Subdomain Takeover check",
    "live_hosts": "Live host probing",
    "waf": "WAF/CDN detection",
    "urls": "URL collection",
    "parameters": "Parameter extraction",
    "ranking": "Priority ranking",
    "passive_scan": "Passive analysis",
    "active_scan": "Active probing",
    "semgrep": "Static analysis (Semgrep)",
    "validation": "Validation runtime",
    "intelligence": "Intelligence merge",
    "threat_modeling": "Threat modeling enrichment",
    "access_control": "Authorization bypass detection",
    "git_diff_crawl": "Incremental git-diff URL filter",
    "sarif_export": "SARIF 2.1 export for CI consumers",
    "reporting": "Report generation",
}


# Per-stage timeouts in seconds.  Used by ``orchestrator._resolve_stage_timeout``
# unless a ``StageNode.timeout`` override is supplied (currently none are).
STAGE_TIMEOUTS = {
    "subdomains": 600,
    "live_hosts": 900,
    "waf": 120,
    "urls": 900,
    "parameters": 120,
    "ranking": 60,
    "passive_scan": 300,
    "active_scan": 900,
    "semgrep": 600,
    "validation": 300,
    "intelligence": 180,
    "access_control": 600,
    "reporting": 300,
    "nuclei": 600,
    "git_diff_crawl": 30,
    "sarif_export": 30,
}

# Stage timeout reasoning:
# subdomains (600s): DNS enumeration with retries for large scopes
# live_hosts (900s): HTTP probing with batch concurrency for 1000s of hosts
# waf (120s): WAF/CDN active fingerprinting probes
# urls (900s): URL collection from multiple sources with rate limiting
# parameters (120s): Fast parameter extraction from collected URLs
# ranking (60s): Lightweight scoring and prioritization
# passive_scan (300s): Passive analysis with external API lookups
# active_scan (900s): Active probing with multiple tool categories
# semgrep (600s): Static analysis with multiple rule sets
# validation (300s): Runtime validation of findings
# intelligence (180s): Threat intel feed aggregation and correlation
# access_control (600s): Authorization bypass detection across auth flows
# reporting (300s): Report generation and export
# nuclei (600s): Nuclei vulnerability scanning with custom templates

# Declared execution order.  Used by tests, dashboards, and the
# ``stage_index`` field of progress events.  The scheduler itself is
# not constrained by this order — the graph topology governs.
STAGE_ORDER = (
    "subdomains",
    "subdomain_takeover",
    "live_hosts",
    "waf",
    "urls",
    "git_diff_crawl",
    "parameters",
    "ranking",
    "passive_scan",
    "active_scan",
    "semgrep",
    "nuclei",
    "access_control",
    "validation",
    "intelligence",
    "threat_modeling",
    "reporting",
    "sarif_export",
)


DEFAULT_ITERATION_LIMIT = 3
DEFAULT_TIMEOUT_SECONDS = 3600


def _build_default_graph() -> Graph:
    """Construct the canonical pipeline graph.

    The graph is built by merging built-in nodes with any stages
    registered in the global StageRegistry. Registered nodes take
    precedence over built-in nodes with the same name.

    Optionally reads ``.ai/capability_manifest.json``
    ``pipeline_profiles.default`` section to gate stages.
    """
    profile = _load_capability_profile("default")
    return build_pipeline_graph(profile=profile)


STAGE_GRAPH: Graph = _build_default_graph()


def _derive_stage_deps(graph: Graph) -> dict[str, frozenset[str]]:
    """Project the graph down to the legacy ``{stage: deps}`` mapping.

    The projection is computed at import time and frozen.  Dashboards
    and plugins that still read ``STAGE_DEPS`` get a stable snapshot;
    the ``ActorScheduler`` does not consult this mapping at all.
    """
    return {node.name: frozenset(node.needs) for node in graph.nodes}


STAGE_DEPS: dict[str, frozenset[str]] = _derive_stage_deps(STAGE_GRAPH)
