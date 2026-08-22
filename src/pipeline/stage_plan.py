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
