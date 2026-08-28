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
from typing import Any, cast

logger = logging.getLogger(__name__)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.pipeline.stage_registry import StageNodeDefinition

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
        name="recon_validation",
        needs=("urls",),
        weight=1,
        timeout=30,
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
            "semgrep",
            "subdomain_takeover",
            "active_scan",
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
        profile = profiles.get(profile_name)
        if not isinstance(profile, dict) or not profile:
            return None
        return cast(dict[str, Any], profile)
    except Exception as exc:
        logger.debug("Failed to load capability profile %r: %s", profile_name, exc)
        return None


def _apply_profile_to_definition(
    defn: StageNodeDefinition,
    profile: dict[str, Any],
) -> StageNodeDefinition:
    """Apply profile settings to a stage definition."""
    from src.pipeline.stage_registry import StageNodeDefinition

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


class GraphBuilder:
    """Doc-facing name for ``build_pipeline_graph``."""

    @staticmethod
    def build(profile: dict[str, Any] | None = None) -> Any:
        return build_pipeline_graph(profile=profile)


def build_pipeline_graph(
    registered_stages: list[StageNodeDefinition] | None = None,
    profile: dict[str, Any] | None = None,
    stage_methods: Mapping[str, Any] | None = None,
    tool_status: dict[str, bool] | None = None,
) -> Graph:
    from src.pipeline.stage_registry import (
        _global_stage_registry,
        _make_stage_node,
        _register_builtin_stages,
    )

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
        if stage_node.name in nodes_by_name:
            builtin_node = nodes_by_name[stage_node.name]
            # I-GRAPH-06: Plugin override safety validation
            # Monotonicity check: plugin cannot drop built-in needs
            builtin_needs_set = set(builtin_node.needs)
            plugin_needs_set = set(stage_node.needs)
            if not builtin_needs_set.issubset(plugin_needs_set):
                dropped = builtin_needs_set - plugin_needs_set
                raise ValueError(
                    f"I-GRAPH-06 Plugin override violation: stage '{stage_node.name}' drops required dependencies {dropped}"
                )
            # Criticality preservation: plugin cannot weaken a critical built-in stage
            if builtin_node.critical and not stage_node.critical:
                raise ValueError(
                    f"I-GRAPH-06 Plugin override violation: stage '{stage_node.name}' cannot unset critical=True"
                )
        nodes_by_name[stage_node.name] = stage_node

    nodes = list(nodes_by_name.values())

    # Prune unavailable tools
    if tool_status:
        available_set = {name for name, avail in tool_status.items() if avail}
        pruned_stages = set()
        for node in list(nodes):
            required_tool = {"nuclei": "nuclei", "semgrep": "semgrep"}.get(node.name)
            if required_tool and required_tool not in available_set:
                if node.critical:
                    raise ValueError(
                        f"I-GRAPH-04/06: Cannot prune critical stage '{node.name}' due to missing tool '{required_tool}'"
                    )
                nodes = [n for n in nodes if n.name != node.name]
                pruned_stages.add(node.name)
                logger.info(
                    "graph_builder: pruning stage '%s' — required tool '%s' not available",
                    node.name,
                    required_tool,
                )
        if pruned_stages:
            import dataclasses

            new_nodes = []
            for n in nodes:
                if any(p in n.needs for p in pruned_stages):
                    new_needs = tuple(dep for dep in n.needs if dep not in pruned_stages)
                    n = dataclasses.replace(n, needs=new_needs)
                new_nodes.append(n)
            nodes = new_nodes

    nodes = _join_finding_producers(nodes)
    return Graph(nodes=tuple(nodes))


_FINDING_PRODUCER_STAGES: frozenset[str] = frozenset(
    {
        "semgrep",
        "subdomain_takeover",
        "active_scan",
        "sca_scan",
        "container_scan",
        "iac_scan",
        "git_secret_scan",
        "nuclei",
        "access_control",
        "validation",
        "passive_scan",
        "intelligence",
        "threat_modeling",
    }
)
_REPORT_SINKS: frozenset[str] = frozenset({"reporting", "sarif_export", "ci_export", "dedup_stage"})


def _produces_findings(defn: Any) -> bool:
    produces = getattr(defn, "produces", None) or []
    return any("finding" in str(item).lower() for item in produces)


def _join_finding_producers(nodes: list[StageNode]) -> list[StageNode]:
    """Make ``reporting.needs`` the set of every finding-producing node."""
    import dataclasses

    names = {n.name for n in nodes}
    reporting = next((n for n in nodes if n.name == "reporting"), None)
    if reporting is None:
        return nodes
    extra: list[str] = []
    for node in nodes:
        if node.name in _REPORT_SINKS:
            continue
        if node.name in _FINDING_PRODUCER_STAGES:
            extra.append(node.name)
    from src.pipeline.stage_registry import _global_stage_registry

    for defn in _global_stage_registry.get_all():
        if defn.name in names and defn.name not in _REPORT_SINKS and _produces_findings(defn):
            extra.append(defn.name)
    merged = tuple(
        dict.fromkeys(
            dep for dep in (*reporting.needs, *extra) if dep in names and dep != "reporting"
        )
    )
    if merged == reporting.needs:
        return nodes
    return [
        dataclasses.replace(node, needs=merged) if node.name == "reporting" else node
        for node in nodes
    ]


def register_plugin_stages() -> None:
    """Register plugin stages at import time. Plugins may call this to
    inject their stage definitions into the global registry."""
    from src.pipeline.stage_registry import _global_stage_registry

    logger.debug(
        "register_plugin_stages called; global registry contains %d entries",
        len(_global_stage_registry.get_all()),
    )
