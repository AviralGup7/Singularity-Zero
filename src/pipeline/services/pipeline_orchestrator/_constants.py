"""Constants and configuration for pipeline orchestration.

The Neural-Mesh executable graph lives in ``STAGE_GRAPH`` and is the
single source of truth for dependencies, conditional gating, and
priority weights.  ``STAGE_ORDER`` and ``PIPELINE_STAGES`` are derived
from the graph at import time; ``STAGE_TIMEOUTS``, ``STAGE_DEPS``, and
``DEFAULT_*`` remain as stable constants used by the timeout resolver,
dashboards, and plugins.
"""

from __future__ import annotations

import logging
from typing import Any
from typing import Any

from ._graph_dsl import Graph
from .graph_builder import _load_capability_profile, build_pipeline_graph

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


def _build_default_graph(profile: dict[str, Any] | None = None) -> Graph:
    if profile is None:
        profile = _load_capability_profile("default")
    return build_pipeline_graph(profile=profile)


STAGE_GRAPH: Graph = _build_default_graph()

STAGE_ORDER = STAGE_GRAPH.topological_sort()
STAGE_ORDER_INDEX: dict[str, int] = {name: idx for idx, name in enumerate(STAGE_ORDER)}
_graph_names = set(STAGE_GRAPH.names())
_order_names = set(STAGE_ORDER)
if _graph_names != _order_names:
    logger.warning(
        "STAGE_ORDER derived from graph does not cover all graph nodes: "
        "graph=%r order=%r diff_in=%r diff_out=%r",
        sorted(_graph_names),
        sorted(STAGE_ORDER),
        sorted(_graph_names - _order_names),
        sorted(_order_names - _graph_names),
    )
try:
    from src.pipeline.services.stage_registry import PIPELINE_STAGES as _SR_STAGES

    _legacy_labels = {s.key: s.label for s in _SR_STAGES}
except Exception as exc:
    logger.debug("stage_registry import failed, falling back to graph node names: %s", exc)
    _legacy_labels = {}
PIPELINE_STAGES = {
    node.name: _legacy_labels.get(node.name, node.name.replace("_", " ").title())
    for node in STAGE_GRAPH.nodes
}

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

STAGE_DEPS: dict[str, frozenset[str]] = {
    node.name: frozenset(node.needs) for node in STAGE_GRAPH.nodes
}

DEFAULT_ITERATION_LIMIT = 3
DEFAULT_TIMEOUT_SECONDS = 3600
