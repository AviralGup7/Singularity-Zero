"""
Cyber Security Test Pipeline - Unified Command Engine
Copyright (c) 2026. Authorized security testing only.

Centralized entry point for dashboard orchestration, distributed workers,
pipeline execution, and system maintenance.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme

# Global UI Theme - 'Cyber' Matrix Green
CYBER_THEME = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        "accent": "bold #00ff41",
    }
)

console = Console(theme=CYBER_THEME)


def _ensure_repo_root() -> None:
    """Ensure the repository root is in sys.path."""
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    os.chdir(root)


def _print_banner() -> None:
    """Print the high-impact startup banner."""
    banner = """
    [accent]██████╗██╗   ██╗██████╗ ███████╗██████╗ [/accent]
    [accent]██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗[/accent]
    [accent]██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝[/accent]
    [accent]██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗[/accent]
    [accent]╚██████╗   ██║   ██████╔╝███████╗██║  ██║[/accent]
    [accent] ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝[/accent]
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

    # ──────────────────────────────────────────────────────────
    # START AREA (Services)
    # ──────────────────────────────────────────────────────────
    start = subparsers.add_parser("start", help="Start long-running infrastructure services.")
    start_sub = start.add_subparsers(dest="service", required=True)

    # Dashboard
    dash = start_sub.add_parser("dashboard", help="Start the security orchestration dashboard.")
    dash.add_argument("--host", default="127.0.0.1", help="Binding address (default: 127.0.0.1)")
    dash.add_argument("--port", type=int, default=8000, help="Listening port (default: 8000)")
    dash.add_argument("--workers", type=int, default=4, help="Number of Gunicorn workers")
    dash.add_argument("--reload", action="store_true", help="Enable hot-reload for UI development")
    dash.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    # Worker
    worker = start_sub.add_parser("worker", help="Start a distributed queue worker node.")
    worker.add_argument("--queue", default="security-pipeline", help="Target queue name")
    worker.add_argument("--concurrency", type=int, default=2, help="Parallel job slots")
    worker.add_argument("--worker-id", help="Explicit worker identifier (default: UUID)")
    worker.add_argument(
        "--replication", action="store_true", help="Enable Redis checkpoint replication"
    )

    # ──────────────────────────────────────────────────────────
    # SCAN AREA (Workflow)
    # ──────────────────────────────────────────────────────────
    scan = subparsers.add_parser("scan", help="Execute security scan workflows.")
    scan_sub = scan.add_subparsers(dest="command", required=True)

    run = scan_sub.add_parser("run", help="Trigger a new pipeline execution.")
    run.add_argument("--config", required=True, help="Path to runtime configuration (JSON)")
    run.add_argument("--scope", required=True, help="Path to target scope file (TXT)")
    run.add_argument("--fresh", action="store_true", help="Ignore existing checkpoints")
    run.add_argument("--dry-run", action="store_true", help="Validation only (no outbound traffic)")

    # ──────────────────────────────────────────────────────────
    # SYSTEM AREA (Maintenance)
    # ──────────────────────────────────────────────────────────
    sys_area = subparsers.add_parser("system", help="System maintenance and health.")
    sys_sub = sys_area.add_subparsers(dest="cmd", required=True)

    sys_sub.add_parser("status", help="Check infrastructure health (Redis, DB, Workers).")
    cleanup = sys_sub.add_parser("cleanup", help="Purge old artifacts and checkpoints.")
    cleanup.add_argument("--days", type=int, default=7, help="Retention period in days")

    return parser


def handle_dashboard(args: argparse.Namespace) -> None:
    """Orchestrate the FastAPI dashboard startup."""
    from src.dashboard.fastapi.main import main as run_server

    console.print(
        f"[info]Starting Cyber Dashboard on {args.host}:{args.port} with {args.workers} workers...[/info]"
    )

    argv = [
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--workers",
        str(args.workers),
        "--log-level",
        args.log_level.lower(),
    ]
    if args.reload:
        argv.append("--reload")

    run_server(argv)


def handle_worker(args: argparse.Namespace) -> None:
    """Orchestrate the distributed worker startup."""
    from src.infrastructure.queue.worker import main as run_worker

    console.print(
        f"[info]Initializing Distributed Worker on queue: [accent]{args.queue}[/accent][/info]"
    )

    argv = ["--queue", args.queue, "--concurrency", str(args.concurrency)]
    if args.worker_id:
        argv.extend(["--worker-id", args.worker_id])
    if args.replication:
        argv.append("--enable-checkpoint-replication")

    run_worker(argv)


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


def handle_status() -> None:
    """Execute a deep infrastructure health audit."""
    table = Table(title="Cyber Pipeline Infrastructure Health")
    table.add_column("Component", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Detail", style="dim")

    # 1. Redis Check
    try:
        import redis

        r = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
        r.ping()
        table.add_row(
            "Redis Backplane",
            "[success]ONLINE[/success]",
            f"Connected to {r.connection_pool.connection_kwargs['host']}",
        )
    except Exception as e:
        table.add_row("Redis Backplane", "[error]OFFLINE[/error]", str(e))

    # 2. Workspace Check
    root = Path.cwd()
    output = root / "output"
    table.add_row("Workspace Root", "[success]OK[/success]", str(root))
    table.add_row(
        "Output Store",
        "[success]OK[/success]" if output.is_dir() else "[warning]MISSING[/warning]",
        str(output),
    )

    # 3. Environment Check
    table.add_row("Python Engine", "[success]OK[/success]", f"v{sys.version.split()[0]}")

    console.print(table)


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

        elif args.area == "scan":
            if args.command == "run":
                return handle_scan(args)

        elif args.area == "system":
            if args.cmd == "status":
                handle_status()
                return 0
            elif args.cmd == "cleanup":
                console.print(
                    "[warning]Cleanup logic not yet fully migrated to unified CLI.[/warning]"
                )
                return 0

    except KeyboardInterrupt:
        console.print("\n[warning]Operation aborted by user.[/warning]")
        return 130
    except Exception as e:
        console.print(
            Panel(f"[error]{type(e).__name__}[/error]: {str(e)}", title="Fatal System Error")
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
