"""Cyber Security Test Pipeline - System area commands (status, doctor, setup, cleanup, plugin)."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

from src.cli.types import Namespace
from src.cli.ui import console

logger = logging.getLogger(__name__)


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

    table.add_row(
        "Python Engine", "[success]OK[/success]", f"v{__import__('sys').version.split()[0]}"
    )

    console.print(table)


def handle_doctor() -> int:
    """Run environment and configuration health checks."""
    import sys

    from rich.panel import Panel
    from rich.table import Table

    from src.pipeline.tools import resolve_tool_path

    root = Path(__file__).resolve().parents[3]
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
                # Defense-in-depth: validate resolved path has no traversal or shell metacharacters
                bin_path_obj = Path(bin_exec).resolve()
                if ".." in str(bin_path_obj) or any(c in str(bin_path_obj) for c in "|;&$`"):
                    raise ValueError(f"Rejected suspicious binary path: {bin_exec}")
                _args: list[str] = [str(bin_path_obj), "--version"]
                result = subprocess.run(  # noqa: S603
                    _args,
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=5,
                )
                ver = " ".join((result.stdout or result.stderr).strip().splitlines())
                version_parts.append(f"{binary} {ver.split()[0] if ver else '?'}")
            except Exception as exc:
                logger.debug("Binary %s unavailable: %s", binary, exc)
                version_parts.append(f"{binary} ?")
        checks.append(("System Binaries", "[success]PASS[/success]", "; ".join(version_parts)))

    redis_detail = ""
    try:
        import redis

        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        r = redis.from_url(redis_url)
        r.ping()
        redis_detail = f"Connected to {r.connection_pool.connection_kwargs['host']}"
        checks.append(("Redis Connectivity", "[success]PASS[/success]", redis_detail))
    except Exception as exc:
        redis_detail = (
            "Redis offline; queue will use the SQLite fallback "
            "(output/local_queue.db). This is not a full-stack pass."
        )
        logger.debug("Redis connection failed: %s", exc)
        checks.append(("Redis Connectivity", "[warning]WARN[/warning]", redis_detail))

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

    has_warning = any("WARN" in status for _, status, _ in checks)
    if exit_code == 0 and not has_warning:
        console.print("[success]PASS[/success] All doctor checks passed.")
    elif exit_code == 0:
        console.print("[warning]WARN[/warning] Doctor finished with warnings.")
    else:
        console.print(
            Panel(
                "[error]FAIL[/error] One or more doctor checks failed.",
                title="Doctor Summary",
            )
        )

    return exit_code


def handle_setup(args: Namespace) -> int:
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


def handle_cleanup(args: Namespace) -> int:
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


def handle_dlq(args: Namespace) -> int:
    """List / replay / purge the durable outbox DLQ."""
    from src.core.outbox.dlq import DurableDLQ

    path = Path(getattr(args, "dlq_path", None) or "output/outbox_dlq.json")
    dlq = DurableDLQ(path)
    action = str(getattr(args, "dlq_action", "list") or "list")
    if action == "list":
        rows = dlq.list()
        console.print(f"[info]DLQ depth={len(rows)} path={path}[/info]")
        for row in rows[:200]:
            console.print(
                f"  {row.delivery_id} event={row.event_id} reason={row.reason} retries={row.retries}"
            )
        return 0
    if action == "replay":
        did = str(getattr(args, "delivery_id", "") or "")
        if getattr(args, "all", False):
            n = 0
            for row in dlq.list():
                if dlq.replay(row.delivery_id, dispatch=lambda rec: None):
                    n += 1
            console.print(f"[success]Replayed {n} DLQ row(s).[/success]")
            return 0
        if not did:
            console.print("[error]replay requires --id or --all[/error]")
            return 2
        ok = dlq.replay(did, dispatch=lambda rec: None)
        console.print("[success]Replayed.[/success]" if ok else "[warning]Not found.[/warning]")
        return 0 if ok else 1
    if action == "purge":
        older = float(getattr(args, "older_than", 7 * 86400) or 7 * 86400)
        dry = not bool(getattr(args, "force", False))
        n = dlq.purge(older_than_seconds=older, dry_run=dry)
        mode = "would purge" if dry else "purged"
        console.print(f"[info]{mode} {n} row(s) (dry-run={dry})[/info]")
        return 0
    console.print(f"[error]Unknown DLQ action {action}[/error]")
    return 2


def handle_finalize_crashed(args: Namespace) -> int:
    """Emit partial reports for CRASHED_IN_PROGRESS DAG checkpoints."""
    from src.core.checkpoint.dag_checkpoint import detect_crashed_runs
    from src.reporting.partial import emit_partial_report

    root = Path(getattr(args, "output_root", None) or "output")
    crashed = detect_crashed_runs(root)
    if not crashed:
        console.print("[info]No crashed-in-progress runs.[/info]")
        return 0
    for snap in crashed:
        result = emit_partial_report(
            snap.run_id, "finalize-crashed", output_dir=root, include_findings=True
        )
        console.print(
            f"[success]Finalized {snap.run_id} findings={result.findings_emitted} dir={result.directory}[/success]"
        )
    return 0


def handle_plugin_new(args: Namespace) -> int:
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

    import keyword
    import re

    if not re.fullmatch(r"[a-z][a-z0-9_]*", name or "") or keyword.iskeyword(name):
        console.print(
            "[error]ERROR: Plugin name must be a valid Python identifier "
            "(start with a letter, then letters/digits/underscore).[/error]"
        )
        return 1

    category = args.category

    console.print(
        f"[info]Scaffolding custom [accent]{category}[/accent] plugin: [accent]{name}[/accent]...[/info]"
    )

    repo_root = Path(__file__).resolve().parents[3]
    src_dir = repo_root / "src"
    if category == "recon":
        target_path = src_dir / "recon" / "sources" / f"{name}.py"
        target_path.parent.mkdir(parents=True, exist_ok=True)
        code = f'''"""Custom recon source plugin: {name}.

Auto-generated by cyber plugin new scaffolding engine.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


async def query_{name}(domain: str, *, timeout: int = 30) -> set[str]:  # noqa: F722
    """Return a set of discovered subdomains/URLs for ``domain``.

    Args:
        domain: Root domain to enumerate.
        timeout: Network timeout in seconds.

    Returns:
        A ``set`` of subdomain/URL strings. Empty on error.
    """
    # TODO: Implement custom recon scanning logic
    logger.info("%s: noop recon source for %s", name, domain)
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

    src_root = src_dir.resolve()
    resolved_target = target_path.resolve()
    if not resolved_target.is_relative_to(src_root):
        console.print("[error]ERROR: Plugin path escaped the source tree.[/error]")
        return 1
    target_path = resolved_target
    target_path.write_text(code, encoding="utf-8")

    registry_path = repo_root / "configs" / "plugins" / "registry.json"
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_data = []
    if registry_path.exists():
        try:
            registry_data = json.loads(registry_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Corrupt registry.json; resetting to empty list: %s", exc)
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
