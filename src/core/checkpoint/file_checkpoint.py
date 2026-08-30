"""Atlas name FileCheckpoint — alias of CheckpointManager."""

from __future__ import annotations

from src.core.checkpoint.manager import CheckpointManager

FileCheckpoint = CheckpointManager

__all__ = ["CheckpointManager", "FileCheckpoint"]
