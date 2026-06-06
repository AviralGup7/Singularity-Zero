"""Cyber Security Test Pipeline - Scan area commands."""

from __future__ import annotations

import argparse

from src.cli.ui import console


def handle_scan(args: argparse.Namespace) -> int:
    """Execute a localized pipeline run."""
    from src.pipeline.runtime import main as run_pipeline

    console.print(f"[info]Launching Pipeline Run: [accent]{args.config}[/accent][/info]")

    argv = ["--config", args.config, "--scope", args.scope]
    if args.fresh:
        argv.append("--force-fresh-run")
    if args.dry_run:
        argv.append("--dry-run")

    return run_pipeline(argv)
