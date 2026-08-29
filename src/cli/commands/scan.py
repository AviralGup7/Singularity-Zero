"""Cyber Security Test Pipeline - Scan area commands."""

from __future__ import annotations

from src.cli.types import Namespace
from src.cli.ui import console


def handle_resume(args: Namespace) -> int:
    """Resume a crashed/incomplete run from DAG + checkpoint state."""
    from src.pipeline.runtime import main as run_pipeline

    console.print(f"[info]Resuming run [accent]{args.run_id}[/accent][/info]")
    argv = [
        "--config",
        args.config,
        "--scope",
        args.scope,
        "--resume-from",
        args.run_id,
    ]
    return run_pipeline(argv)


def handle_scan(args: Namespace) -> int:
    """Execute a localized pipeline run."""
    from src.pipeline.runtime import main as run_pipeline

    console.print(f"[info]Launching Pipeline Run: [accent]{args.config}[/accent][/info]")

    argv = ["--config", args.config, "--scope", args.scope]
    if args.fresh:
        argv.append("--force-fresh-run")
    if args.dry_run:
        argv.append("--dry-run")
    if getattr(args, "frontier_only", False):
        argv.append("--frontier-only")

    return run_pipeline(argv)
