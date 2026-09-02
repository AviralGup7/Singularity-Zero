"""Automated online backup and disaster recovery for SQLite and WAL (Item 13).

Provides live online snapshotting using sqlite3.Connection.backup() without write locking,
SHA-256 manifest verification, and point-in-time disaster recovery restore.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class SqliteOnlineBackupService:
    """Non-blocking live backup of SQLite databases using sqlite3.Connection.backup."""

    @staticmethod
    def backup_database(source_db_path: Path | str, target_backup_path: Path | str) -> dict[str, Any]:
        """Create a point-in-time consistent snapshot of an active SQLite database."""
        source = Path(source_db_path)
        target = Path(target_backup_path)
        if not source.exists():
            raise FileNotFoundError(f"Source database does not exist: {source}")

        target.parent.mkdir(parents=True, exist_ok=True)
        started_at = time.time()

        src_conn = sqlite3.connect(str(source))
        try:
            dst_conn = sqlite3.connect(str(target))
            try:
                src_conn.backup(dst_conn, pages=100)
            finally:
                dst_conn.close()
        finally:
            src_conn.close()

        # Compute SHA-256 digest
        hasher = hashlib.sha256()
        with open(target, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        digest = hasher.hexdigest()

        manifest = {
            "source_path": str(source),
            "backup_path": str(target),
            "sha256": digest,
            "size_bytes": target.stat().st_size,
            "created_at": started_at,
            "duration_seconds": round(time.time() - started_at, 3),
        }
        manifest_path = target.with_suffix(".manifest.json")
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        logger.info("Successfully backed up %s -> %s (sha256: %s)", source, target, digest[:8])
        return manifest

    @staticmethod
    def restore_database(backup_path: Path | str, target_db_path: Path | str) -> bool:
        """Restore a database snapshot with SHA-256 manifest integrity verification."""
        backup = Path(backup_path)
        target = Path(target_db_path)
        if not backup.exists():
            raise FileNotFoundError(f"Backup file does not exist: {backup}")

        # Verify integrity against manifest if present
        manifest_path = backup.with_suffix(".manifest.json")
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            expected_hash = manifest.get("sha256")
            if expected_hash:
                hasher = hashlib.sha256()
                with open(backup, "rb") as f:
                    while chunk := f.read(65536):
                        hasher.update(chunk)
                if hasher.hexdigest() != expected_hash:
                    raise ValueError(f"Integrity check failed for backup {backup}")

        target.parent.mkdir(parents=True, exist_ok=True)
        src_conn = sqlite3.connect(str(backup))
        try:
            dst_conn = sqlite3.connect(str(target))
            try:
                src_conn.backup(dst_conn, pages=100)
            finally:
                dst_conn.close()
        finally:
            src_conn.close()
        logger.info("Successfully restored database %s -> %s", backup, target)
        return True
