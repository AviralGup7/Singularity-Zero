"""Pipeline graph builder.

Single source of truth for the executable pipeline DAG. Replaces
``STAGE_DEPS`` + ``PARALLEL_STAGE_GROUPS`` + ``_check_parallel_consistency()``
with one declarative :class:`Graph` whose nodes carry their
dependencies, conditional gates, priority weights, timeouts, and
criticality flag.

The builder takes the runtime method map (so the ``startup`` node is
injected only when a startup method is actually registered) and
returns an immutable, cycle-checked :class:`Graph`.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from src.pipeline.stage_registry import (
    StageNodeDefinition,
    _global_stage_registry,
    _make_stage_node,
)

from ._graph_dsl import (
    All,
    FlagSet,
    Graph,
    OutputNonEmpty,
    StageNode,
)

# Stage timeout reasoning (matches legacy STAGE_TIMEOUTS comments):
#   subdomains (600s):   DNS enumeration with retries for large scopes
#   live_hosts (900s):   HTTP probing with batch concurrency for 1000s of hosts
#   waf (120s):          WAF/CDN active fingerprinting probes
#   urls (900s):         URL collection from multiple sources with rate limiting
#   parameters (120s):   Fast parameter extraction from collected URLs
#   ranking (60s):       Lightweight scoring and prioritization
#   passive_scan (300s): Passive analysis with external API lookups
#   active_scan (900s):  Active probing with multiple tool categories
#   semgrep (600s):      Static analysis with multiple rule sets
#   validation (300s):   Runtime validation of findings
#   intelligence (180s): Threat intel feed aggregation and correlation
#   access_control (600s): Authorization bypass detection across auth flows
#   reporting (300s):    Report generation and export
#   nuclei (600s):       Nuclei vulnerability scanning with custom templates

# Critical-path priorities.  Weight is the per-node priority band used
# by the ActorScheduler when multiple nodes become ready at the same
# tick.  Convention: long-running stages on the critical path get
# the worker pool first so they can start their IO as soon as
# possible, even before short sibling stages finish.  Active stages
# (active_scan, nuclei, semgrep, access_control) are explicitly
# raised above passive stages because they produce the high-value
# findings the operator is waiting for.
_BASE_NODES: tuple[StageNode, ...] = (
    StageNode(
        name="subdomains",
        needs=(),
        weight=10,
        timeout=600,
        critical=False,
    ),
    StageNode(
        name="live_hosts",
        needs=("subdomains",),
        weight=15,
        timeout=900,
        critical=True,
    ),
    StageNode(
        name="waf",
        needs=("live_hosts",),
        weight=2,
        timeout=120,
    ),
    StageNode(
        name="urls",
        needs=("live_hosts",),
        weight=15,
        timeout=900,
        critical=False,
    ),
    StageNode(
        name="git_diff_crawl",
        needs=("urls",),
        weight=1,
        timeout=30,
    ),
    StageNode(
        name="parameters",
        needs=("urls",),
        weight=2,
        timeout=120,
    ),
    StageNode(
        name="ranking",
        needs=("urls", "parameters", "waf"),
        weight=1,
        timeout=60,
    ),
    StageNode(
        name="passive_scan",
        needs=("ranking", "live_hosts", "urls"),
        weight=5,
        timeout=300,
    ),
    StageNode(
        name="active_scan",
        needs=("passive_scan",),
        weight=15,
        timeout=900,
        when=OutputNonEmpty("live_hosts"),
    ),
    StageNode(
        name="semgrep",
        needs=("passive_scan",),
        weight=10,
        timeout=600,
        when=OutputNonEmpty("live_hosts"),
    ),
    StageNode(
        name="subdomain_takeover",
        needs=("subdomains",),
        weight=8,
        timeout=300,
    ),
    StageNode(
        name="nuclei",
        needs=("passive_scan",),
        weight=10,
        timeout=600,
        when=All(
            conditions=(
                OutputNonEmpty("live_hosts"),
                FlagSet("nuclei_available"),
            ),
        ),
    ),
    StageNode(
        name="access_control",
        needs=("ranking", "passive_scan"),
        weight=10,
        timeout=600,
        when=OutputNonEmpty("live_hosts"),
    ),
    StageNode(
        name="validation",
        needs=("passive_scan", "active_scan"),
        weight=5,
        timeout=300,
    ),
    StageNode(
        name="intelligence",
        needs=("passive_scan", "active_scan", "nuclei", "validation"),
        weight=3,
        timeout=180,
    ),
    StageNode(
        name="threat_modeling",
        needs=("intelligence",),
        weight=4,
        timeout=300,
    ),
    StageNode(
        name="reporting",
        needs=(
            "intelligence",
            "nuclei",
            "access_control",
            "validation",
            "passive_scan",
            "threat_modeling",
        ),
        weight=5,
        timeout=300,
    ),
    StageNode(
        name="sarif_export",
        needs=("reporting",),
        weight=1,
        timeout=30,
    ),
)


def _load_capability_profile(profile_name: str) -> dict[str, Any] | None:
    """Load a named pipeline profile from .ai/capability_manifest.json if present."""
    manifest_path = Path(".ai/capability_manifest.json")
    if not manifest_path.exists():
        return None
    try:
        text = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(text)
        profiles = manifest.get("pipeline_profiles", {})
        return profiles.get(profile_name)
    except Exception as exc:
        logger.debug("Failed to load capability profile %r: %s", profile_name, exc)
        return None


def _apply_profile_to_definition(
    defn: StageNodeDefinition,
    profile: dict[str, Any],
) -> StageNodeDefinition:
    """Apply profile settings to a stage definition."""
    stage_profile = profile.get(defn.name)
    if not isinstance(stage_profile, dict):
        return defn

    # Merge with base definition (overrides take precedence)
    merged = StageNodeDefinition(
        name=defn.name,
        needs=list(defn.needs),
        weight=stage_profile.get("weight", defn.weight),
        timeout_seconds=stage_profile.get("timeout_seconds", defn.timeout_seconds),
        critical=stage_profile.get("critical", defn.critical),
        when=defn.when,
        runner_name=defn.runner_name,
        produces=list(defn.produces),
        group=defn.group,
    )

    # Apply 'enabled' as a FlagSet condition
    enabled = stage_profile.get("enabled")
    if enabled is False:
        flag = FlagSet(flag=f"{defn.name}_enabled")
        if merged.when is None:
            merged = StageNodeDefinition(
                name=merged.name,
                needs=merged.needs,
                weight=merged.weight,
                timeout_seconds=merged.timeout_seconds,
                critical=merged.critical,
                when=flag,
                runner_name=merged.runner_name,
                produces=merged.produces,
                group=merged.group,
            )
        else:
            combined = All(conditions=(merged.when, flag))
            merged = StageNodeDefinition(
                name=merged.name,
                needs=merged.needs,
                weight=merged.weight,
                timeout_seconds=merged.timeout_seconds,
                critical=merged.critical,
                when=combined,
                runner_name=merged.runner_name,
                produces=merged.produces,
                group=merged.group,
            )

    return merged


def build_pipeline_graph(
    registered_stages: list[StageNodeDefinition] | None = None,
    profile: dict[str, Any] | None = None,
    stage_methods: Mapping[str, Any] | None = None,
    tool_status: dict[str, bool] | None = None,
) -> Graph:
    from src.pipeline.stage_registry import _register_builtin_stages

    _register_builtin_stages()
    # Load registered stages if not provided explicitly
    if registered_stages is None:
        registered_stages = _global_stage_registry.get_all()

    # Start with built-in nodes
    nodes_by_name: dict[str, StageNode] = {n.name: n for n in _BASE_NODES}

    # Merge plugin stages (plugin nodes override built-in nodes with same name)
    for defn in registered_stages:
        # Apply profile if provided
        effective_defn = defn
        if profile is not None:
            effective_defn = _apply_profile_to_definition(defn, profile)

        stage_node = _make_stage_node(effective_defn)
        nodes_by_name[stage_node.name] = stage_node

    nodes = list(nodes_by_name.values())

    # Prune unavailable tools
    if tool_status:
        available_set = {name for name, avail in tool_status.items() if avail}
        for node in list(nodes):
            required_tool = {"nuclei": "nuclei", "semgrep": "semgrep"}.get(node.name)
            if required_tool and required_tool not in available_set:
                nodes = [n for n in nodes if n.name != node.name]
                logger.info(
                    "graph_builder: pruning stage '%s' — required tool '%s' not available",
                    node.name,
                    required_tool,
                )

    return Graph(nodes=tuple(nodes))


def register_plugin_stages() -> None:
    """Register plugin stages at import time. Plugins may call this to
    inject their stage definitions into the global registry."""
    logger.debug("register_plugin_stages called; global registry contains %d entries",
                 len(_global_stage_registry.get_all()))
