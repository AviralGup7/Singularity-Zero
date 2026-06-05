"""Constants and configuration for pipeline orchestration.

The Neural-Mesh executable graph lives in ``STAGE_GRAPH`` and is the
single source of truth for dependencies, conditional gating, and
priority weights.  The legacy ``STAGE_DEPS`` mapping is now derived
from the graph for backward compatibility with dashboards and
plugins; new code should import ``STAGE_GRAPH`` directly.
"""
from __future__ import annotations

from ._graph_dsl import Graph
from .graph_builder import build_pipeline_graph

__all__ = [
    "PIPELINE_STAGES",
    "STAGE_ORDER",
    "STAGE_TIMEOUTS",
    "STAGE_DEPS",
    "STAGE_GRAPH",
    "DEFAULT_ITERATION_LIMIT",
    "DEFAULT_TIMEOUT_SECONDS",
]


PIPELINE_STAGES = {
    "subdomains": "Subdomain enumeration",
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
    "access_control": "Authorization bypass detection",
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
    "live_hosts",
    "waf",
    "urls",
    "parameters",
    "ranking",
    "passive_scan",
    "active_scan",
    "semgrep",
    "nuclei",
    "access_control",
    "validation",
    "intelligence",
    "reporting",
)

DEFAULT_ITERATION_LIMIT = 3
DEFAULT_TIMEOUT_SECONDS = 3600


def _build_default_graph() -> Graph:
    """Construct the canonical pipeline graph.

    The graph is built without a ``stage_methods`` mapping, so the
    ``startup`` node is not injected.  Callers that need startup
    injection (e.g. the orchestrator) should call
    :func:`graph_builder.build_pipeline_graph` directly.
    """
    return build_pipeline_graph()


STAGE_GRAPH: Graph = _build_default_graph()


def _derive_stage_deps(graph: Graph) -> dict[str, frozenset[str]]:
    """Project the graph down to the legacy ``{stage: deps}`` mapping.

    The projection is computed at import time and frozen.  Dashboards
    and plugins that still read ``STAGE_DEPS`` get a stable snapshot;
    the ``ActorScheduler`` does not consult this mapping at all.
    """
    return {node.name: frozenset(node.needs) for node in graph.nodes}


STAGE_DEPS: dict[str, frozenset[str]] = _derive_stage_deps(STAGE_GRAPH)
