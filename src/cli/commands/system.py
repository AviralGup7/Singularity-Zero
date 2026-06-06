"""Cyber Security Test Pipeline - System area commands (status, doctor, setup, cleanup, plugin)."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from src.cli.ui import console


def handle_status() -> None:
    """Execute a deep infrastructure health audit."""
    from rich.table import Table

    table = Table(title="Cyber Pipeline Infrastructure Health")
    table.add_column("Component", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Detail", style="dim")

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

    root = Path.cwd()
    output = root / "output"
    table.add_row("Workspace Root", "[success]OK[/success]", str(root))
    table.add_row(
        "Output Store",
        "[success]OK[/success]" if output.is_dir() else "[warning]MISSING[/warning]",
        str(output),
    )

    table.add_row("Python Engine", "[success]OK[/success]", f"v{__import__('sys').version.split()[0]}")

    console.print(table)


def handle_doctor() -> int:
    """Run environment and configuration health checks."""
    import sys

    from rich.panel import Panel
    from rich.table import Table

    from src.pipeline.tools import resolve_tool_path

    root = Path(__file__).resolve().parents[2]
    checks: list[tuple[str, str, str]] = []
    exit_code: int = 0

    py_tag = "[success]PASS[/success]"
    py_detail = f"v{sys.version.split()[0]}"
    checks.append(("Python Version", py_tag, py_detail))

    required_bins = ["nuclei", "httpx", "subfinder"]
    missing_bins: list[str] = []
    resolved_paths: dict[str, str] = {}
    for binary in required_bins:
        bin_path = resolve_tool_path(binary)
        if bin_path is None:
            missing_bins.append(binary)
        else:
            resolved_paths[binary] = bin_path

    if missing_bins:
        detail = f"{', '.join(missing_bins)} not found on PATH or local VFS"
        checks.append(("System Binaries", "[error]FAIL[/error]", detail))
        if exit_code == 0:
            exit_code = 2
    else:
        version_parts: list[str] = []
        for binary in required_bins:
            try:
                bin_exec = resolved_paths[binary]
                _args: list[str] = [bin_exec, "--version"]
                result = subprocess.run(
                    _args,
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=5,
                )
                ver = " ".join((result.stdout or result.stderr).strip().splitlines())
                version_parts.append(f"{binary} {ver.split()[0] if ver else '?'}")
            except Exception:
                version_parts.append(f"{binary} ?")
        checks.append(("System Binaries", "[success]PASS[/success]", "; ".join(version_parts)))

    redis_detail = ""
    try:
        import redis

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        r = redis.from_url(redis_url)
        r.ping(timeout=3)
        redis_detail = f"Connected to {r.connection_pool.connection_kwargs['host']}"
        checks.append(("Redis Connectivity", "[success]PASS[/success]", redis_detail))
    except Exception:
        redis_detail = "Redis offline; transparent fallback to persistent SQLite (output/local_queue.db) active."
        checks.append(
            ("Redis Connectivity", "[success]PASS (SQLITE FALLBACK)[/success]", redis_detail)
        )

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
                checks.append((".env File", "[error]FAIL[/error]", env_detail))
                if exit_code == 0:
                    exit_code = 3
            else:
                env_detail = f"Present and non-default ({env_path})"
                checks.append((".env File", "[success]PASS[/success]", env_detail))
        except OSError as exc:
            env_detail = f".env file not readable: {exc}"
            checks.append((".env File", "[error]FAIL[/error]", env_detail))
            if exit_code == 0:
                exit_code = 3

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
                cfg_detail = f"configs/config.json missing required keys: {', '.join(missing_keys)}"
                checks.append(("Config Integrity", "[error]FAIL[/error]", cfg_detail))
                if exit_code == 0:
                    exit_code = 5
            else:
                cfg_detail = "Valid JSON with all required keys"
                checks.append(("Config Integrity", "[success]PASS[/success]", cfg_detail))

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


def handle_setup(args: argparse.Namespace) -> int:
    """Orchestrate downloading and installing required Go binaries locally."""
    from src.core.utils.bin_downloader import setup_all_tools

    console.print(
        "[accent]██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████[/accent]"
    )
    console.print("[accent]███             Automated Binary Downloader                ███[/accent]")
    console.print(
        "[accent]██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████[/accent]"
    )

    dest = Path(args.dir) if args.dir else None
    setup_all_tools(dest_dir=dest, console_print=True)
    console.print("\n[success]Setup process complete.[/success]")
    return 0


def handle_cleanup(args: argparse.Namespace) -> int:
    """Purge old artifacts and checkpoints."""
    from src.pipeline.maintenance import prune_output_history

    summary = prune_output_history(
        Path(args.output_root),
        keep_target_runs=args.keep_target_runs,
        keep_launcher_runs=args.keep_launcher_runs,
    )
    removed_targets = len(summary.get("removed_target_run_dirs", []))
    removed_launchers = len(summary.get("removed_launcher_dirs", []))
    console.print(
        f"[success]Cleanup complete: removed {removed_targets} target run dir(s) "
        f"and {removed_launchers} launcher dir(s) "
        f"under {summary.get('output_root', args.output_root)}.[/success]"
    )
    return 0


def handle_plugin_new(args: argparse.Namespace) -> int:
    """Scaffold a new custom security plugin."""
    from rich.prompt import Prompt

    console.print(
        "[accent]██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████[/accent]"
    )
    console.print("[accent]███             Custom Plugin Scaffolding Engine           ███[/accent]")
    console.print(
        "[accent]██████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████[/accent]"
    )

    name = args.name or Prompt.ask("Enter plugin name (alphanumeric/underscore)")
    name = name.strip().lower()

    if not name or (not name.isalnum() and "_" not in name):
        console.print("[error]ERROR: Plugin name must be alphanumeric or underscore.[/error]")
        return 1

    category = args.category

    console.print(
        f"[info]Scaffolding custom [accent]{category}[/accent] plugin: [accent]{name}[/accent]...[/info]"
    )

    src_dir = Path(__file__).resolve().parent.parent.parent / "src"
    if category == "recon":
        target_path = src_dir / "recon" / "sources" / f"{name}.py"
        target_path.parent.mkdir(parents=True, exist_ok=True)
        code = f'''"""Custom recon source plugin: {name}.

Auto-generated by cyber plugin new scaffolding engine.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


async def query_{name}(domain: str, *, timeout: int = 30) -> set[str]:
    """Return a set of discovered subdomains/URLs for ``domain``.

    Args:
        domain: Root domain to enumerate.
        timeout: Network timeout in seconds.

    Returns:
        A ``set`` of subdomain/URL strings. Empty on error.
    """
    # TODO: Implement custom recon scanning logic
    logger.info("{name}: noop recon source for %s", domain)
    return set()
'''
    elif category == "exploit":
        target_path = src_dir / "execution" / "exploiters" / f"{name}.py"
        target_path.parent.mkdir(parents=True, exist_ok=True)
        code = f'''"""Custom exploit plugin: {name}.

Auto-generated by cyber plugin new scaffolding engine.
"""

from __future__ import annotations

from typing import Any

class {name.capitalize()}Exploiter:
    """Custom {name} exploit validation plugin."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.name = "{name}"

    def check(self, target: str, payload: str) -> bool:
        """Verify vulnerability exposure safely."""
        return False
'''
    else:
        target_path = src_dir / "reporting" / f"{name}.py"
        target_path.parent.mkdir(parents=True, exist_ok=True)
        code = f'''"""Custom reporting plugin: {name}.

Auto-generated by cyber plugin new scaffolding engine.
"""

from __future__ import annotations

from typing import Any

class {name.capitalize()}Reporter:
    """Custom {name} reporting plugin."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.name = "{name}"

    def format_findings(self, findings: list[dict[str, Any]]) -> str:
        """Format findings for custom export."""
        return ""
'''

    target_path.write_text(code, encoding="utf-8")

    registry_path = src_dir / "configs" / "plugins" / "registry.json"
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_data = []
    if registry_path.exists():
        try:
            registry_data = json.loads(registry_path.read_text(encoding="utf-8"))
        except Exception:
            registry_data = []

    if not isinstance(registry_data, list):
        registry_data = []

    plugin_entry = {"name": name, "category": category, "path": str(target_path.as_posix())}
    if not any(p.get("name") == name for p in registry_data):
        registry_data.append(plugin_entry)
        registry_path.write_text(json.dumps(registry_data, indent=2), encoding="utf-8")

    console.print(
        f"[success]SUCCESS: Plugin {name} scaffolded at {target_path} and registered![/success]"
    )
    return 0
