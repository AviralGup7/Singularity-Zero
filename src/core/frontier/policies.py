"""
Cyber Security Test Pipeline - Ghost-VFS Policies
Retention policy engine for enforcing storage metrics.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.frontier.ghost_vfs import GhostVFS

logger = logging.getLogger(__name__)


class PolicyEngine:
    """
    Manages and enforces retention metrics (maximum age, maximum count, and cumulative size)
    for GhostVFS virtual files.
    """

    def __init__(
        self,
        max_age_seconds: float = 86400.0,  # Default 24 hours
        max_file_count: int = 1000,
        max_total_bytes: int = 50 * 1024 * 1024,  # Default 50 MB
    ) -> None:
        self.max_age_seconds = max_age_seconds
        self.max_file_count = max_file_count
        self.max_total_bytes = max_total_bytes

    def enforce_retention(self, vfs: GhostVFS) -> None:
        """
        Scan virtual file system, evaluate retention rules, and prune files that violate
        the metrics.
        """
        now = time.time()
        expired_paths: list[str] = []

        # Gather file metrics securely
        file_metrics: list[tuple[float, int, str]] = []  # (created_at, size, path)

        for path in vfs.list_files():
            # Retrieve creation time if tracked, else default to current epoch
            created_at = now
            if hasattr(vfs, "_file_metadata") and path in vfs._file_metadata:
                created_at = vfs._file_metadata[path].get("created_at", now)

            # Age check
            if now - created_at > self.max_age_seconds:
                expired_paths.append(path)
                continue

            try:
                # We can check size by looking at the encrypted file length
                size = len(vfs._files.get(path, b""))
            except Exception:
                size = 0

            file_metrics.append((created_at, size, path))

        # Delete age-expired files
        for path in expired_paths:
            try:
                vfs.delete_file(path)
                logger.info("PolicyEngine: Pruned age-expired file %s", path)
            except Exception as e:
                logger.error("PolicyEngine: Failed to delete age-expired file %s: %s", path, e)

        # Sort active files by creation time ascending (oldest first)
        file_metrics.sort()

        # Enforce max file count
        while len(file_metrics) > self.max_file_count:
            _, _, path = file_metrics.pop(0)
            try:
                vfs.delete_file(path)
                logger.info("PolicyEngine: Pruned file %s due to file count limit", path)
            except Exception as e:
                logger.error(
                    "PolicyEngine: Failed to delete file %s under count policy: %s", path, e
                )

        # Enforce max total bytes
        total_bytes = sum(size for _, size, _ in file_metrics)
        while total_bytes > self.max_total_bytes and file_metrics:
            _, size, path = file_metrics.pop(0)
            try:
                vfs.delete_file(path)
                total_bytes -= size
                logger.info("PolicyEngine: Pruned file %s due to total bytes limit", path)
            except Exception as e:
                logger.error(
                    "PolicyEngine: Failed to delete file %s under size policy: %s", path, e
                )
