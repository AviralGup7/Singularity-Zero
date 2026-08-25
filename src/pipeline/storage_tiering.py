"""Scan artifact retention: hot NVMe/cache → compressed archive."""

from __future__ import annotations

import gzip
import logging
import shutil
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def archive_run_dir(run_dir: Path, archive_root: Path, *, compress: bool = True) -> Path:
    """Move a completed run directory into the archive tier."""
    archive_root.mkdir(parents=True, exist_ok=True)
    dest = archive_root / run_dir.name
    if dest.exists():
        dest = archive_root / f"{run_dir.name}-{int(time.time())}"
    shutil.copytree(run_dir, dest, dirs_exist_ok=True)
    if compress:
        for path in dest.rglob("*"):
            if path.is_file() and path.suffix not in {".gz", ".zip"} and path.stat().st_size > 4096:
                gz = path.with_suffix(path.suffix + ".gz")
                with path.open("rb") as src, gzip.open(gz, "wb") as out:
                    shutil.copyfileobj(src, out)
                path.unlink()
    logger.info("Archived run %s -> %s", run_dir, dest)
    return dest


def prune_hot_tier(hot_root: Path, *, max_age_seconds: float = 86400.0 * 14) -> int:
    """Delete hot-tier run dirs older than max_age_seconds. Returns removed count."""
    now = time.time()
    removed = 0
    if not hot_root.exists():
        return 0
    for child in hot_root.iterdir():
        if not child.is_dir():
            continue
        try:
            age = now - child.stat().st_mtime
        except OSError:
            continue
        if age > max_age_seconds:
            shutil.rmtree(child, ignore_errors=True)
            removed += 1
    return removed
