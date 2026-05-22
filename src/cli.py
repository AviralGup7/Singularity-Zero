"""
Cyber Security Test Pipeline - Unified Command Engine
Copyright (c) 2026. Authorized security testing only.

Centralized entry point for dashboard orchestration, distributed workers,
pipeline execution, and system maintenance.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
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
    sys_sub.add_parser("doctor", help="Run environment and configuration health checks.")
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

    return run_pipeline(argv)  # type: ignore[no-any-return]


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


def handle_doctor() -> int:
    """Run environment and configuration health checks."""
    root = Path.cwd()
    checks: list[tuple[str, str, str]] = []  # (label, status_markup, detail)
    exit_code: int = 0

    # ── Check 1: Python version ──────────────────────────────────
    py_tag = "[success]PASS[/success]"
    py_detail = f"v{sys.version.split()[0]}"
    if sys.version_info < (3, 14):
        py_tag = "[error]FAIL[/error]"
        py_detail = (
            f"Python >= 3.14 required, found {sys.version.split()[0]}"
        )
        if exit_code == 0:
            exit_code = 2
    checks.append(("Python Version", py_tag, py_detail))

    # ── Check 2: System binaries ─────────────────────────────────
    required_bins = ["nuclei", "httpx", "subfinder"]
    missing_bins: list[str] = []
    for binary in required_bins:
        bin_path = shutil.which(binary)
        if bin_path is None:
            missing_bins.append(binary)
    if missing_bins:
        detail = f"{', '.join(missing_bins)} not found on PATH"
        checks.append(("System Binaries", "[error]FAIL[/error]", detail))
        if exit_code == 0:
            exit_code = 2
    else:
        version_parts: list[str] = []
        for binary in required_bins:
            try:
                _args: list[str] = [binary, "--version"]
                result = subprocess.run(  # noqa: S603
                    _args,
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=5,
                )
                ver = " ".join(
                    (result.stdout or result.stderr).strip().splitlines()
                )
                version_parts.append(f"{binary} {ver.split()[0] if ver else '?'}")
            except Exception:
                version_parts.append(f"{binary} ?")
        checks.append(
            ("System Binaries", "[success]PASS[/success]", "; ".join(version_parts))
        )

    # ── Check 3: Redis connectivity ──────────────────────────────
    redis_detail = ""
    try:
        import redis as _redis

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        r = _redis.from_url(redis_url)
        r.ping(timeout=3)
        redis_detail = f"Connected to {r.connection_pool.connection_kwargs['host']}"
        checks.append(("Redis Connectivity", "[success]PASS[/success]", redis_detail))
    except Exception as exc:
        redis_detail = f"Redis not reachable: {exc}"
        checks.append(("Redis Connectivity", "[error]FAIL[/error]", redis_detail))
        if exit_code == 0:
            exit_code = 4

    # ── Check 4: .env file ────────────────────────────────────────
    env_path = root / ".env"
    env_detail = ""
    if not env_path.exists() or not env_path.is_file():
        env_detail = f".env file not found at {env_path}"
        checks.append((".env File", "[error]FAIL[/error]", env_detail))
        if exit_code == 0:
            exit_code = 3
    else:
        try:
            content = env_path.read_text(encoding="utf-8", errors="replace")
            bad_defaults = [
                "change-me-in-production",
                "REPLACE_WITH_SECURE_USERNAME",
                "REPLACE_WITH_SECURE_PASSWORD",
            ]
            found_bad = [
                line
                for line in content.splitlines()
                if any(placeholder in line for placeholder in bad_defaults)
            ]
            if found_bad:
                env_detail = ".env contains default/placeholder values"
                checks.append(
                    (".env File", "[error]FAIL[/error]", env_detail)
                )
                if exit_code == 0:
                    exit_code = 3
            else:
                env_detail = f"Present and non-default ({env_path})"
                checks.append(
                    (".env File", "[success]PASS[/success]", env_detail)
                )
        except OSError as exc:
            env_detail = f".env file not readable: {exc}"
            checks.append((".env File", "[error]FAIL[/error]", env_detail))
            if exit_code == 0:
                exit_code = 3

    # ── Check 5: Config integrity ────────────────────────────────
    cfg_path = root / "configs" / "config.json"
    cfg_detail = ""
    if not cfg_path.exists() or not cfg_path.is_file():
        cfg_detail = f"configs/config.json not found at {cfg_path}"
        checks.append(("Config Integrity", "[error]FAIL[/error]", cfg_detail))
        if exit_code == 0:
            exit_code = 5
    else:
        try:
            cfg_data = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception as exc:
            cfg_detail = f"configs/config.json is not valid JSON: {exc}"
            checks.append(("Config Integrity", "[error]FAIL[/error]", cfg_detail))
            if exit_code == 0:
                exit_code = 5
        else:
            required_keys = [
                "target_name",
                "output_dir",
                "tools",
                "http_timeout_seconds",
                "nuclei",
            ]
            missing_keys = [k for k in required_keys if k not in cfg_data]
            if missing_keys:
                cfg_detail = (
                    f"configs/config.json missing required keys: {', '.join(missing_keys)}"
                )
                checks.append(
                    ("Config Integrity", "[error]FAIL[/error]", cfg_detail)
                )
                if exit_code == 0:
                    exit_code = 5
            else:
                cfg_detail = "Valid JSON with all required keys"
                checks.append(
                    ("Config Integrity", "[success]PASS[/success]", cfg_detail)
                )

    # ── Print results table ──────────────────────────────────────
    table = Table(title="Cyber Doctor Health Report")
    table.add_column("Check", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Detail", style="dim")
    for label, status, detail in checks:
        table.add_row(label, status, detail)
    console.print(table)

    if exit_code == 0:
        console.print("[success]PASS[/success] All doctor checks passed.")
    else:
        console.print(
            Panel(
                "[error]FAIL[/error] One or more doctor checks failed.",
                title="Doctor Summary",
            )
        )

    return exit_code


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
            elif args.cmd == "doctor":
                return handle_doctor()
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
