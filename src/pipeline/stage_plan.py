"""Honor wizard module selection without inventing a second DAG.

Wizard checkboxes are *tools* (subfinder, nuclei, …), not pipeline stage
keys. Recon/analysis stages still run when their dependencies require them.
Optional tool-gated stages are dropped when the matching tool is disabled.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

# Stages that only exist to drive a specific optional tool.
TOOL_GATED_STAGES: dict[str, str] = {
    "nuclei": "nuclei",
    "semgrep": "semgrep",
}

# Always kept when present — they feed later optional work.
MANDATORY_STAGES: frozenset[str] = frozenset(
    {
        "startup",
        "subdomains",
        "live_hosts",
        "urls",
        "recon_validation",
        "parameters",
        "ranking",
        "passive_scan",
        "reporting",
        "sarif_export",
    }
)


def enabled_tools(config: Mapping[str, Any] | Any) -> dict[str, bool]:
    raw = config.get("tools") if isinstance(config, Mapping) else getattr(config, "tools", {})
    if not isinstance(raw, Mapping):
        return {}
    return {str(name): bool(enabled) for name, enabled in raw.items()}


def constrain_remaining_stages(
    remaining: Iterable[str],
    *,
    config: Mapping[str, Any] | Any | None = None,
    selected_modules: Iterable[str] | None = None,
) -> list[str]:
    """Drop tool-gated stages whose tool is not selected/enabled.

    Unknown stages pass through. Mandatory recon/reporting stages stay even
    if the operator only ticked ``nuclei``.
    """
    tools = enabled_tools(config or {})
    selected = {str(item).strip() for item in (selected_modules or []) if str(item).strip()}
    planned: list[str] = []
    for stage in remaining:
        gate = TOOL_GATED_STAGES.get(stage)
        if gate is None:
            planned.append(stage)
            continue
        if selected and gate not in selected:
            continue
        if gate in tools and not tools[gate]:
            continue
        planned.append(stage)
    return planned


def export_stage_graph() -> dict[str, Any]:
    """Serialize the orchestrator DAG for the dashboard theater."""
    from src.pipeline.services.pipeline_orchestrator._constants import (
        PIPELINE_STAGES,
        STAGE_DEPS,
        STAGE_ORDER,
    )

    edges: list[list[str]] = []
    for name, deps in STAGE_DEPS.items():
        for dep in sorted(deps):
            edges.append([str(dep), str(name)])
    levels = _levels_from_deps({name: set(deps) for name, deps in STAGE_DEPS.items()}, list(STAGE_ORDER))
    return {
        "nodes": [str(name) for name in STAGE_ORDER],
        "edges": edges,
        "levels": levels,
        "labels": {str(k): str(v) for k, v in PIPELINE_STAGES.items()},
    }


def _levels_from_deps(deps: dict[str, set[str]], order: list[str]) -> list[list[str]]:
    level_of: dict[str, int] = {}
    for name in order:
        preds = [dep for dep in deps.get(name, set()) if dep in level_of or dep in deps]
        if not preds:
            level_of[name] = 0
            continue
        level_of[name] = 1 + max((level_of.get(dep, 0) for dep in preds), default=0)
    buckets: dict[int, list[str]] = {}
    for name in order:
        buckets.setdefault(level_of.get(name, 0), []).append(name)
    return [buckets[idx] for idx in sorted(buckets)]


def merge_tool_status(
    tool_status: Mapping[str, Any] | None,
    config: Mapping[str, Any] | Any | None,
) -> dict[str, Any]:
    """AND binary availability with config.tools so unchecked tools stay off."""
    merged: dict[str, Any] = dict(tool_status or {})
    for name, enabled in enabled_tools(config or {}).items():
        if not enabled:
            current = merged.get(name)
            if isinstance(current, dict):
                merged[name] = {**current, "available": False, "enabled": False}
            else:
                merged[name] = False
    return merged
