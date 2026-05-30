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

    return config, scope_entries, tool_status, flow_manifest
