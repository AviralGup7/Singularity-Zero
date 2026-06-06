"""Cyber Security Test Pipeline - CLI entrypoint."""

from __future__ import annotations

import sys

if sys.platform.startswith("win") and "pytest" not in sys.modules:
    import io

    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import argparse

from src.cli.commands.scan import handle_scan
from src.cli.commands.start import handle_dashboard, handle_launch, handle_worker
from src.cli.commands.system import (
    handle_cleanup,
    handle_doctor,
    handle_plugin_new,
    handle_setup,
    handle_status,
)
from src.cli.ui import console


def _ensure_repo_root() -> None:
    """Ensure the repository root is in sys.path."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))


def _print_banner() -> None:
    """Print the high-impact startup banner."""
    banner = """
    [accent]███████████████████████████████   ██████████████████████████████ █████████████████████████████████████████████████ [/accent]
    [accent]████████████████████████████████████ ████████████████████████████████████████████████████████████████████████████████████[/accent]
    [accent]█████████      █████████████████████ ██████████████████████████████████████████  ████████████████████████[/accent]
    [accent]█████████       ███████████████  ██████████████████████████████████████████  ████████████████████████[/accent]
    [accent]████████████████████████   █████████   █████████████████████████████████████████████████████████  █████████[/accent]
    [accent] █████████████████████   █████████   █████████████████████████████████████████ █████████████████████████████████  █████████[/accent]
    [dim]Unified Security Orchestration Engine v2.0.0[/dim]
    """
    console.print(banner)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyber",
        description="Unified Cyber Security Test Pipeline Command Engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="area", required=True)

    start = subparsers.add_parser("start", help="Start long-running infrastructure services.")
    start_sub = start.add_subparsers(dest="service", required=True)

    dash = start_sub.add_parser("dashboard", help="Start the security orchestration dashboard.")
    dash.add_argument("--host", default="127.0.0.1", help="Binding address (default: 127.0.0.1)")
    dash.add_argument("--port", type=int, default=8000, help="Listening port (default: 8000)")
    dash.add_argument("--workers", type=int, default=4, help="Number of Gunicorn workers")
    dash.add_argument("--reload", action="store_true", help="Enable hot-reload for UI development")
    dash.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    worker = start_sub.add_parser("worker", help="Start a distributed queue worker node.")
    worker.add_argument("--queue", default="security-pipeline", help="Target queue name")
    worker.add_argument("--concurrency", type=int, default=2, help="Parallel job slots")
    worker.add_argument("--worker-id", help="Explicit worker identifier (default: UUID)")
    worker.add_argument(
        "--replication", action="store_true", help="Enable Redis checkpoint replication"
    )

    scan = subparsers.add_parser("scan", help="Execute security scan workflows.")
    scan_sub = scan.add_subparsers(dest="command", required=True)

    run = scan_sub.add_parser("run", help="Trigger a new pipeline execution.")
    run.add_argument("--config", required=True, help="Path to runtime configuration (JSON)")
    run.add_argument("--scope", required=True, help="Path to target scope file (TXT)")
    run.add_argument("--fresh", action="store_true", help="Ignore existing checkpoints")
    run.add_argument("--dry-run", action="store_true", help="Validation only (no outbound traffic)")

    sys_area = subparsers.add_parser("system", help="System maintenance and health.")
    sys_sub = sys_area.add_subparsers(dest="cmd", required=True)

    sys_sub.add_parser("status", help="Check infrastructure health (Redis, DB, Workers).")
    sys_sub.add_parser("doctor", help="Run environment and configuration health checks.")
    setup = sys_sub.add_parser(
        "setup",
        help="Auto-detect operating system/architecture and download pre-compiled Go binaries (nuclei, httpx, subfinder) locally.",
    )
    setup.add_argument(
        "--dir",
        default=None,
        help="Directory to install binaries to (default: workspace .tools/bin)",
    )
    cleanup = sys_sub.add_parser("cleanup", help="Purge old artifacts and checkpoints.")
    cleanup.add_argument("--days", type=int, default=7, help="Retention period in days")
    cleanup.add_argument(
        "--output-root",
        default="output",
        help="Path to the output directory to prune (default: output).",
    )
    cleanup.add_argument(
        "--keep-target-runs",
        type=int,
        default=2,
        help="How many recent target runs to keep per target.",
    )
    cleanup.add_argument(
        "--keep-launcher-runs",
        type=int,
        default=5,
        help="How many recent launcher job directories to keep.",
    )

    launch = subparsers.add_parser(
        "launch", help="Start the dashboard and background queue worker in a single process."
    )
    launch.add_argument("--host", default="127.0.0.1", help="Binding address (default: 127.0.0.1)")
    launch.add_argument("--port", type=int, default=8000, help="Listening port (default: 8000)")
    launch.add_argument(
        "--concurrency", type=int, default=2, help="Worker concurrency slots (default: 2)"
    )
    launch.add_argument(
        "--queue",
        default="security-pipeline",
        help="Target queue name (default: security-pipeline)",
    )

    plugin = subparsers.add_parser("plugin", help="Manage custom security scanning plugins.")
    plugin_sub = plugin.add_subparsers(dest="cmd", required=True)

    plugin_new = plugin_sub.add_parser("new", help="Scaffold a new custom security plugin.")
    plugin_new.add_argument("--name", help="Name of the new plugin")
    plugin_new.add_argument(
        "--category",
        choices=["recon", "exploit", "reporting"],
        default="recon",
        help="Plugin category (default: recon)",
    )

    return parser


def main() -> int:
    _ensure_repo_root()
    _print_banner()

    parser = _build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    args = parser.parse_args()

    try:
        if args.area == "start":
            if args.service == "dashboard":
                handle_dashboard(args)
            elif args.service == "worker":
                handle_worker(args)

        elif args.area == "launch":
            handle_launch(args)
            return 0

        elif args.area == "scan":
            if args.command == "run":
                return handle_scan(args)

        elif args.area == "plugin":
            if args.cmd == "new":
                return handle_plugin_new(args)

        elif args.area == "system":
            if args.cmd == "status":
                handle_status()
                return 0
            elif args.cmd == "doctor":
                return handle_doctor()
            elif args.cmd == "setup":
                return handle_setup(args)
            elif args.cmd == "cleanup":
                return handle_cleanup(args)

    except KeyboardInterrupt:
        console.print("\n[warning]Operation aborted by user.[/warning]")
        return 130
    except Exception as e:
        from rich.panel import Panel

        console.print(
            Panel(f"[error]{type(e).__name__}[/error]: {str(e)}", title="Fatal System Error")
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
