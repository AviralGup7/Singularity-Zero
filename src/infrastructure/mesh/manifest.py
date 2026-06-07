"""
Worker capability and topology manifest for the Neural-Mesh.

Replaces hard-coded capability lists with a real manifest sourced from
(in priority order):

1. The ``MESH_CAPABILITIES`` environment variable - a comma-separated
   list, e.g. ``MESH_CAPABILITIES=browser,nuclei,semgrep,sqlmap``.
2. The dynamic plugin registry (``src.core.plugins.registry``) - every
   registered plugin's ``kind`` becomes an inferred capability and any
   ``capabilities`` metadata is merged in.
3. Tool availability on ``PATH`` - the names listed in
   ``DEFAULT_TOOL_PROBES`` are checked with :func:`shutil.which` and
   reported when present.

Geographic / capacity hints are sourced from ``MESH_REGION``,
``MESH_ZONE``, ``MESH_BANDWIDTH_MBPS``, and ``MESH_CAPACITY_WEIGHT``.

The manifest is intentionally cheap to compute, deterministic per
process, and side-effect free so the gossip layer can re-publish it
without contention.
"""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


DEFAULT_TOOL_PROBES: tuple[str, ...] = (
    "nuclei",
    "semgrep",
    "subfinder",
    "httpx",
    "naabu",
    "katana",
    "sqlmap",
    "ffuf",
    "amass",
    "trivy",
    "gobuster",
)


@dataclass(frozen=True)
class WorkerManifest:
    """Locally-discovered worker capability and topology manifest."""

    capabilities: list[str] = field(default_factory=list)
    region: str = ""
    zone: str = ""
    bandwidth_mbps: float = 0.0
    capacity_weight: float = 1.0


def _split_csv(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _capabilities_from_env() -> list[str]:
    return _split_csv(os.getenv("MESH_CAPABILITIES"))


def _capabilities_from_plugins() -> list[str]:
    """Best-effort enumeration of plugin-provided capabilities.

    Imports the plugin registry lazily so this module can be used
    in contexts where the plugin loader is not available (tests,
    minimal CLI bootstrap, etc.).
    """
    capabilities: set[str] = set()
    try:
        from src.core.plugins.registry import GLOBAL_PLUGIN_REGISTRY

        with GLOBAL_PLUGIN_REGISTRY._lock:  # noqa: SLF001 - reading registry snapshot
            kinds_map = dict(GLOBAL_PLUGIN_REGISTRY._providers)
        for kind, providers in kinds_map.items():
            kind_norm = str(kind).strip().lower()
            if kind_norm:
                capabilities.add(kind_norm)
            for registration in providers.values():
                metadata = getattr(registration, "metadata", {}) or {}
                meta_caps = metadata.get("capabilities") or []
                if isinstance(meta_caps, (list, tuple, set)):
                    for cap in meta_caps:
                        if isinstance(cap, str) and cap.strip():
                            capabilities.add(cap.strip().lower())
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("plugin capability probe failed: %s", exc)
    return sorted(capabilities)


def _capabilities_from_path(
    probes: tuple[str, ...] = DEFAULT_TOOL_PROBES,
) -> list[str]:
    found: list[str] = []
    for tool in probes:
        try:
            if shutil.which(tool):
                found.append(tool.lower())
        except (OSError, ValueError) as exc:
            logger.debug("shutil.which(%s) failed: %s", tool, exc)
    return found


def _float_env(name: str, default: float = 0.0) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        logger.warning("Invalid %s=%r; using %.2f", name, raw, default)
        return default


def discover_manifest(
    *,
    extra_capabilities: list[str] | None = None,
    tool_probes: tuple[str, ...] = DEFAULT_TOOL_PROBES,
) -> WorkerManifest:
    """Assemble a :class:`WorkerManifest` from env, plugins, and PATH.

    Args:
        extra_capabilities: Extra capability tags appended verbatim
            (lower-cased, deduplicated).
        tool_probes: Override the default ``shutil.which`` probe list.
    """
    discovered: set[str] = set()
    discovered.update(_capabilities_from_env())
    discovered.update(_capabilities_from_plugins())
    discovered.update(_capabilities_from_path(tool_probes))
    if extra_capabilities:
        discovered.update(c.strip().lower() for c in extra_capabilities if c and c.strip())

    region = os.getenv("MESH_REGION", "").strip().lower()
    zone = os.getenv("MESH_ZONE", "").strip().lower()
    bandwidth = max(0.0, _float_env("MESH_BANDWIDTH_MBPS", 0.0))
    weight = max(0.1, _float_env("MESH_CAPACITY_WEIGHT", 1.0))

    return WorkerManifest(
        capabilities=sorted(discovered),
        region=region,
        zone=zone,
        bandwidth_mbps=bandwidth,
        capacity_weight=weight,
    )


__all__ = ["DEFAULT_TOOL_PROBES", "WorkerManifest", "discover_manifest"]
