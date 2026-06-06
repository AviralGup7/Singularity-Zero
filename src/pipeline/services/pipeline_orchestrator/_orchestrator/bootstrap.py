"""Pipeline bootstrapping, configuration loading, and preflight checks."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from src.core.config import load_config
from src.pipeline.runner_support import build_tool_status, emit_progress
from src.pipeline.services.stage_registry import pipeline_flow_manifest
from src.pipeline.storage import read_scope


def bootstrap_pipeline(args: argparse.Namespace) -> tuple[Any, list[str], dict[str, Any], Any]:
    """Load config, scope, tool status, and flow manifest during startup."""
    flow_manifest = pipeline_flow_manifest()
    emit_progress("startup", "Loading configuration", 3)

    preloaded_config = getattr(args, "_loaded_config", None)
    config = (
        preloaded_config
        if preloaded_config is not None
        else load_config(Path(args.config).resolve())
    )

    preloaded_scope_entries = getattr(args, "_loaded_scope_entries", None)
    scope_entries = (
        list(preloaded_scope_entries)
        if preloaded_scope_entries is not None
        else read_scope(Path(args.scope).resolve())
    )

    screenshot_cfg = config.screenshots if isinstance(config.screenshots, dict) else {}
    tool_status = build_tool_status(screenshot_cfg.get("browser_paths", []))
    emit_progress("startup", f"Loaded config for {config.target_name}", 8)

    # Perform capability resource validation check
    import os

    import psutil

    from src.pipeline.tools_capabilities import CAPABILITY_REGISTRY

    if not os.environ.get("IGNORE_CAPABILITY_RESOURCE_BUDGET"):
        active_caps = set()
        # subfinder, amass, assetfinder, crtsh -> recon_provider
        if any(config.tools.get(t, True) for t in ("subfinder", "amass", "assetfinder", "crtsh")):
            active_caps.add("recon_provider")
        # httpx -> http_probe_provider
        if config.tools.get("httpx", True):
            active_caps.add("http_probe_provider")
        # katana, gau, waybackurls -> crawler_provider
        if any(config.tools.get(t, True) for t in ("katana", "gau", "waybackurls")):
            active_caps.add("crawler_provider")
        # nuclei -> template_scanner
        if config.tools.get("nuclei", True):
            active_caps.add("template_scanner")

        total_memory_required = 0.0
        for cap in active_caps:
            try:
                manifest = CAPABILITY_REGISTRY.get_manifest(cap)
                total_memory_required += manifest.memory_mb
            except KeyError:
                continue

        available_memory = psutil.virtual_memory().available / (1024 * 1024)
        if total_memory_required > available_memory:
            raise ValueError(
                f"Insufficient host memory to execute the enabled pipeline capabilities. "
                f"Estimated required: {total_memory_required:.1f}MB, "
                f"available: {available_memory:.1f}MB. "
                f"Bypass with IGNORE_CAPABILITY_RESOURCE_BUDGET=1 environment variable."
            )

    return config, scope_entries, tool_status, flow_manifest
