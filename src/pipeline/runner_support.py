import argparse
import json
import logging
from pathlib import Path
from typing import Any

from src.core.logging.pipeline_logging import emit_progress_event
from src.core.models import TOOL_NAMES
from src.pipeline.cache import load_cached_set, save_cached_set
from src.pipeline.screenshots import detect_browser
from src.pipeline.tools import projectdiscovery_httpx_available, tool_available

logger = logging.getLogger(__name__)


def load_adaptive_config(output_dir: Path, target_name: str) -> dict[str, Any]:
    """Load the latest adaptive configuration for a target (Phase 5.2)."""
    adaptive_path = output_dir / target_name / "config.adaptive.json"
    if not adaptive_path.exists():
        return {}

    try:
        with open(adaptive_path, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                logger.info("Loaded adaptive configuration from %s", adaptive_path)
                return data
    except Exception as exc:
        logger.warning("Failed to load adaptive configuration: %s", exc)

    return {}


def emit_progress(stage: str, message: str, percent: int, **fields: object) -> None:
    emit_progress_event(stage, message, percent, **fields)


def emit_stage_summary(stage: str, summary: dict[str, Any]) -> None:
    """Emit a machine-readable stage summary for observability."""
    emit_progress(
        stage,
        f"Stage {stage} summary",
        100,
        stage_status="completed",
        summary_payload=summary,
        event_trigger=f"recon_{stage}_summary",
        telemetry_event_type=f"recon.{stage}.summary",
    )


def emit_url_progress(message: str, percent: int, **fields: object) -> None:
    emit_progress("urls", message, percent, **fields)


def check_max_duration(args: argparse.Namespace, started_at: float) -> bool:
    """Return True if the max-duration budget is exhausted."""
    max_dur = getattr(args, "max_duration_seconds", None)
    if max_dur is None:
        return False
    import time

    return (time.time() - started_at) >= max_dur


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
    parser.add_argument(
        "--validate-config",
        action="store_true",
        dest="validate_config",
        help="Validate config and exit without running pipeline",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        dest="policy",
        help="Path to an ExitConditionPolicy TOML file that gates the run on "
        "finding-severity thresholds. See src.pipeline.services.ci.policy for schema.",
    )
    parser.add_argument(
        "--incremental",
        action="store_true",
        help="Restrict the URL set to URLs that map to files changed since --base-ref.",
    )
    parser.add_argument(
        "--base-ref",
        default=None,
        dest="base_ref",
        help="Git ref (branch / commit / tag) used as the baseline for --incremental.",
    )
    parser.add_argument(
        "--branch",
        default=None,
        help="Current branch name (used by [on_findings] branch_glob in the policy). "
        "Defaults to GITHUB_REF_NAME / CI_COMMIT_REF_NAME when set.",
    )
    parser.add_argument(
        "--legacy-exit-codes",
        action="store_true",
        dest="legacy_exit_codes",
        help="Collapse the 2/3/4 taxonomy back to a single 1 (pre-CI behaviour).",
    )
    parser.add_argument(
        "--resume-from",
        default=None,
        dest="resume_from",
        help="Checkpoint run ID to resume from (skips completed stages).",
    )
    parser.add_argument(
        "--replay-stage",
        default=None,
        dest="replay_stage",
        help="Re-execute only a single stage from a captured run. "
        "Requires --run-id to identify the source run.",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        dest="replay_run_id",
        help="Run ID whose captured stage trace should be replayed.",
    )
    parser.add_argument(
        "--replay-traces",
        default=None,
        dest="replay_traces_run_id",
        help="Load and replay all stages from a traced run ID.",
    )
    parser.add_argument(
        "--trace-dir",
        default=".ai/traces",
        dest="trace_dir",
        help="Directory containing stage trace JSONL files (default: .ai/traces).",
    )
    parser.add_argument(
        "--max-duration",
        type=int,
        default=None,
        dest="max_duration_seconds",
        help="Maximum pipeline wall-clock duration in seconds. Exits with code 3 when exceeded.",
    )
    parser.add_argument(
        "--ci-fail-on-severity",
        default=None,
        dest="ci_fail_on_severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit non-zero when any finding at or above this severity is present in CI export.",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Enable continuous monitoring mode with asset inventory diff-based scanning.",
    )
    parser.add_argument(
        "--monitor-interval",
        type=int,
        default=3600,
        dest="monitor_interval",
        help="Interval between monitoring cycles in seconds (default: 3600).",
    )
    parser.add_argument(
        "--asset-diff-only",
        action="store_true",
        dest="asset_diff_only",
        help="Only scan new/changed assets since the last checkpoint.",
    )
    parser.add_argument(
        "--import-burp-issues",
        type=Path,
        default=None,
        dest="import_burp_issues",
        help="Import Burp Suite issues.xml export into pipeline findings.",
    )
    parser.add_argument(
        "--import-burp-sitemap",
        type=Path,
        default=None,
        dest="import_burp_sitemap",
        help="Import Burp SiteMap JSON export to seed priority URLs.",
    )
    parser.add_argument(
        "--burp-collaborator-url",
        default=None,
        dest="burp_collaborator_url",
        help="Burp Collaborator server URL for OAST polling.",
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
