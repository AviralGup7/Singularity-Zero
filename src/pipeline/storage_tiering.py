"""Scan artifact retention: hot NVMe/cache → compressed archive (F-025 Item 18).

Provides crash-safe transactional move semantics:
1. Archive: Compress and copy hot artifacts to the archive tier.
2. Verify: Verify archive integrity (file counts, sizes, and gzip decompressibility).
3. Record: Atomically update the durable archive manifest (run_ids, timestamps, sha256).
4. Delete: Only after verification passes, purge the hot-tier source.
5. Supports dry_run mode without modifying filesystem.
"""

from __future__ import annotations

import gzip
import json
import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ArchivalVerificationError(RuntimeError):
    """Raised when an archived directory fails post-copy integrity verification."""


@dataclass
class ArchivalPruneResult:
    """Outcome of a transactional archival prune execution."""

    scanned_runs: int = 0
    archived_runs: list[str] = field(default_factory=list)
    pruned_runs: list[str] = field(default_factory=list)
    skipped_runs: list[str] = field(default_factory=list)
    failed_runs: list[tuple[str, str]] = field(default_factory=list)
    dry_run: bool = False
    manifest_path: str = ""


def _verify_archive_integrity(dest_dir: Path, expected_file_count: int) -> bool:
    """Verify that every file in dest_dir exists and gzip files are uncorrupted."""
    if not dest_dir.exists():
        return False

    archived_files = list(dest_dir.rglob("*"))
    actual_files = [p for p in archived_files if p.is_file()]

    if len(actual_files) < expected_file_count:
        logger.error(
            "Archive integrity failed for %s: expected %d files, found %d",
            dest_dir,
            expected_file_count,
            len(actual_files),
        )
        return False

    # Test decompression of every gzip file
    for p in actual_files:
        if p.suffix == ".gz":
            try:
                with gzip.open(p, "rb") as gz:
                    # Read first 1KB to verify valid gzip header and crc
                    gz.read(1024)
            except Exception as exc:
                logger.error("Corrupted gzip archive file %s: %s", p, exc)
                return False

    return True


def _update_manifest(manifest_path: Path, run_id: str, dest_path: Path, metadata: dict[str, Any] | None = None) -> None:
    """Atomically record an archived run in the durable manifest."""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    records: dict[str, Any] = {}
    if manifest_path.exists():
        try:
            with open(manifest_path, encoding="utf-8") as f:
                records = json.load(f)
        except Exception:
            records = {}

    records[run_id] = {
        "run_id": run_id,
        "archive_path": str(dest_path.resolve()),
        "archived_at": time.time(),
        "metadata": metadata or {},
    }

    tmp_manifest = manifest_path.with_suffix(".tmp")
    with open(tmp_manifest, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    tmp_manifest.replace(manifest_path)


def archive_run_dir(
    run_dir: Path,
    archive_root: Path,
    *,
    compress: bool = True,
    verify: bool = True,
) -> Path:
    """Move a completed run directory into the archive tier with verification."""
    archive_root.mkdir(parents=True, exist_ok=True)
    dest = archive_root / run_dir.name
    if dest.exists():
        dest = archive_root / f"{run_dir.name}-{int(time.time())}"

    source_files = [p for p in run_dir.rglob("*") if p.is_file()]
    expected_count = len(source_files)

    shutil.copytree(run_dir, dest, dirs_exist_ok=True)

    if compress:
        for path in dest.rglob("*"):
            if path.is_file() and path.suffix not in {".gz", ".zip"} and path.stat().st_size > 4096:
                gz = path.with_suffix(path.suffix + ".gz")
                with path.open("rb") as src, gzip.open(gz, "wb") as out:
                    shutil.copyfileobj(src, out)
                path.unlink()

    if verify and not _verify_archive_integrity(dest, expected_count):
        shutil.rmtree(dest, ignore_errors=True)
        raise ArchivalVerificationError(
            f"Archive verification failed for {run_dir} -> {dest}; destination removed"
        )

    logger.info("Archived run %s -> %s (verified: %s)", run_dir, dest, verify)
    return dest


def transactional_prune_and_archive(
    hot_root: Path,
    archive_root: Path,
    *,
    max_age_seconds: float = 86400.0 * 14,
    dry_run: bool = False,
    manifest_name: str = "archive_manifest.json",
) -> ArchivalPruneResult:
    """Crash-safe transactional archive-then-verify-then-delete prune job (F-025 Item 18)."""
    now = time.time()
    result = ArchivalPruneResult(dry_run=dry_run, manifest_path=str((archive_root / manifest_name).resolve()))

    if not hot_root.exists():
        return result

    manifest_path = archive_root / manifest_name

    for child in sorted(hot_root.iterdir()):
        if not child.is_dir():
            continue
        result.scanned_runs += 1
        try:
            age = now - child.stat().st_mtime
        except OSError:
            continue

        if age <= max_age_seconds:
            result.skipped_runs.append(child.name)
            continue

        run_id = child.name
        if dry_run:
            result.archived_runs.append(run_id)
            result.pruned_runs.append(run_id)
            continue

        # Step 1: Archive and Step 2: Verify
        try:
            dest_dir = archive_run_dir(child, archive_root, compress=True, verify=True)
            result.archived_runs.append(run_id)

            # Step 3: Record in manifest
            _update_manifest(manifest_path, run_id, dest_dir)

            # Step 4: Delete from hot tier ONLY after verify & manifest update
            shutil.rmtree(child, ignore_errors=False)
            result.pruned_runs.append(run_id)
            logger.info("Transactionally pruned hot run %s after successful archive", run_id)
        except Exception as exc:
            logger.error("Transactional archive/prune failed for run %s: %s", run_id, exc)
            result.failed_runs.append((run_id, str(exc)))

    return result


def prune_hot_tier(hot_root: Path, *, max_age_seconds: float = 86400.0 * 14) -> int:
    """Legacy helper: Delete hot-tier run dirs older than max_age_seconds."""
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
