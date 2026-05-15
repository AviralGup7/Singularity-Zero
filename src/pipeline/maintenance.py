import argparse
import re
import shutil
from pathlib import Path
from typing import Any

from src.core.logging.pipeline_logging import emit_info
from src.core.logging.trace_logging import get_pipeline_logger
from src.pipeline.cache_backend import PersistentCache
from src.reporting import build_dashboard_index, list_run_dirs

logger = get_pipeline_logger(__name__)

RUN_DIR_NAME_RE = re.compile(r"^\d{8}-\d{6}$")


def prune_output_history(
    output_root: Path, *, keep_target_runs: int = 2, keep_launcher_runs: int = 5
) -> dict[str, Any]:
    if keep_target_runs < 1:
        raise ValueError("keep_target_runs must be at least 1.")
    if keep_launcher_runs < 0:
        raise ValueError("keep_launcher_runs must be at least 0.")

    root = output_root.resolve()
    summary: dict[str, Any] = {
        "output_root": str(root),
        "keep_target_runs": keep_target_runs,
        "keep_launcher_runs": keep_launcher_runs,
        "removed_target_run_dirs": [],
        "removed_launcher_dirs": [],
        "updated_target_indexes": [],
    }
    if not root.exists():
        return summary

    for entry in sorted(
        (path for path in root.iterdir() if path.is_dir()), key=lambda path: path.name.lower()
    ):
        if entry.name == "_launcher":
            removed = _prune_launcher_dirs(entry, keep_launcher_runs)
            summary["removed_launcher_dirs"].extend(str(path) for path in removed)
            continue
        if entry.name.startswith("_"):
            continue

        run_dirs = _list_generated_run_dirs(entry)
        stale_runs = run_dirs[:-keep_target_runs] if len(run_dirs) > keep_target_runs else []
        for run_dir in stale_runs:
            _remove_tree(run_dir)
        if stale_runs:
            summary["removed_target_run_dirs"].extend(str(path) for path in stale_runs)

        remaining_runs = list_run_dirs(entry)
        if remaining_runs or (entry / "index.html").exists():
            build_dashboard_index(entry)
            summary["updated_target_indexes"].append(str(entry / "index.html"))

    return summary


def _prune_launcher_dirs(launcher_root: Path, keep_launcher_runs: int) -> list[Path]:
    job_dirs = sorted(
        (path for path in launcher_root.iterdir() if path.is_dir()),
        key=lambda path: (path.stat().st_mtime, path.name),
    )
    stale_dirs = job_dirs[:-keep_launcher_runs] if len(job_dirs) > keep_launcher_runs else []
    for path in stale_dirs:
        _remove_tree(path)
    return stale_dirs


def _list_generated_run_dirs(target_root: Path) -> list[Path]:
    if not target_root.exists():
        return []
    return sorted(
        path
        for path in target_root.iterdir()
        if path.is_dir() and RUN_DIR_NAME_RE.fullmatch(path.name)
    )


def _remove_tree(path: Path) -> None:
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass


def run_cache_maintenance(cache: PersistentCache | None = None) -> dict[str, Any]:
    """Run cache cleanup and return stats.

    Args:
        cache: Cache instance. If None, creates a default one.

    Returns:
        Dict with cleaned_entries, stats, and status.
    """
    if cache is None:
        cache = PersistentCache()

    stats_before = cache.get_cache_stats()
    cleaned = cache.cleanup_expired()
    stats_after = cache.get_cache_stats()

    result: dict[str, Any] = {
        "status": "ok",
        "cleaned_entries": cleaned,
        "stats_before": stats_before,
        "stats_after": stats_after,
    }
    logger.info(
        "Cache maintenance: cleaned %d expired entries, %d active remaining",
        cleaned,
        stats_after.get("active_entries", 0),
    )
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prune stale generated output history.")
    parser.add_argument("--output-root", default="output", help="Path to the output directory.")
    parser.add_argument(
        "--keep-target-runs",
        type=int,
        default=2,
        help="How many recent target runs to keep per target.",
    )
    parser.add_argument(
        "--keep-launcher-runs",
        type=int,
        default=5,
        help="How many recent launcher job directories to keep.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = prune_output_history(
        Path(args.output_root),
        keep_target_runs=args.keep_target_runs,
        keep_launcher_runs=args.keep_launcher_runs,
    )
    emit_info(str(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
