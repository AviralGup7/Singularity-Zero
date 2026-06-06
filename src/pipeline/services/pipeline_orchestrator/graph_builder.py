"""Pipeline graph builder.

Single source of truth for the executable pipeline DAG.  Replaces
``STAGE_DEPS`` + ``PARALLEL_STAGE_GROUPS`` + ``_check_parallel_consistency()``
with one declarative :class:`Graph` whose nodes carry their
dependencies, conditional gates, priority weights, timeouts, and
criticality flag.

The builder takes the runtime method map (so the ``startup`` node is
injected only when a startup method is actually registered) and
returns an immutable, cycle-checked :class:`Graph`.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

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
        # ``subdomains`` is no longer critical: when active subdomain
        # enumeration fails the pipeline can still proceed in degraded
        # mode if a downstream stage (``urls``) surfaces actionable
        # targets via certificate transparency or historical data.
        # The ``RECON_DEGRADED`` warning is emitted from
        # ``resolve_pipeline_exit_code`` and the run is downgraded to
        # ``partial`` (exit 4) instead of ``infra_failure`` (exit 3).
        critical=False,
    ),
    StageNode(
        name="live_hosts",
        needs=("subdomains",),
        weight=15,
        timeout=900,
        # ``live_hosts`` is the only truly fatal recon stage: it gates
        # every active scanner via ``OutputNonEmpty("live_hosts")`` and
        # without it there is nothing to probe.
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
        # ``urls`` is no longer critical: when URL collection fails the
        # pipeline can still complete passively if ``subdomains``
        # produced a non-empty set, or it can fall back to live-host
        # probing directly.  See ``RECON_DEGRADED`` handling in
        # ``resolve_pipeline_exit_code``.
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



def build_pipeline_graph(
    stage_methods: Mapping[str, Any] | None = None,
) -> Graph:
    """Construct the executable pipeline graph.

    The optional ``stage_methods`` mapping lets the builder mirror the
    legacy behaviour: ``startup`` is injected as a node and added to
    ``subdomains.needs`` *only* when a startup method is actually
    registered.  This keeps checkpoint-compat runs that have no
    startup method from being blocked on a phantom dependency.
    """
    nodes: list[StageNode] = list(_BASE_NODES)
    if stage_methods is not None and "startup" in stage_methods:
        nodes.insert(
            0,
            StageNode(
                name="startup",
                needs=(),
                weight=0,
                timeout=0,
            ),
        )
        for index, node in enumerate(nodes):
            if node.name == "subdomains":
                nodes[index] = StageNode(
                    name=node.name,
                    needs=("startup",) + tuple(node.needs),
                    when=node.when,
                    weight=node.weight,
                    timeout=node.timeout,
                    critical=node.critical,
                )
                break
    return Graph(nodes=tuple(nodes))
