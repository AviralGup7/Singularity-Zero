import argparse
from pathlib import Path
from typing import Any

from src.core.logging.pipeline_logging import emit_progress_event
from src.core.models import TOOL_NAMES
from src.pipeline.cache import load_cached_set, save_cached_set
from src.pipeline.screenshots import detect_browser
from src.pipeline.tools import projectdiscovery_httpx_available, tool_available


def emit_progress(stage: str, message: str, percent: int, **fields: object) -> None:
    emit_progress_event(stage, message, percent, **fields)


def emit_url_progress(message: str, percent: int, **fields: object) -> None:
    emit_progress("urls", message, percent, **fields)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Target-specific recon pipeline")
    parser.add_argument("--config", required=True, help="Path to config JSON")
    parser.add_argument("--scope", required=True, help="Path to scope file")
    parser.add_argument("--dry-run", action="store_true", help="Validate config and tools only")
    parser.add_argument("--skip-crtsh", action="store_true", help="Skip crt.sh collection")
    parser.add_argument(
        "--refresh-cache", action="store_true", help="Ignore cached subdomains and URLs"
    )
    parser.add_argument(
        "--force-fresh-run",
        action="store_true",
        help="Ignore checkpoint recovery and start a fresh run",
    )
    parser.add_argument(
        "--replay",
        type=Path,
        default=None,
        dest="replay_archive",
        help="Path to a .tar.gz artifact pack to replay. Unpacks config/scope, "
        "runs with --force-fresh-run, and verifies parity.",
    )
    return parser.parse_args(argv)


def build_tool_status(browser_paths: list[str]) -> dict[str, bool]:
    status = {tool: tool_available(tool) for tool in TOOL_NAMES}
    status["httpx"] = projectdiscovery_httpx_available()
    status["python_http_probe"] = True
    status["browser_for_screenshots"] = bool(detect_browser(browser_paths))
    return status


def resolve_cached_stage(
    cache_path: Path,
    refresh_cache: bool,
    producer: Any,
) -> set[str]:
    if not refresh_cache:
        cached = load_cached_set(cache_path)
        if cached:
            return cached
    produced = producer()
    save_cached_set(cache_path, produced)
    return set(produced)
