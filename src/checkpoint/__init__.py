"""Checkpoint / WAL replay facade over core.checkpoint."""

from __future__ import annotations

from typing import Any


def file_checkpoint_cls() -> Any:
    from src.core.checkpoint.file_checkpoint import FileCheckpoint

    return FileCheckpoint


def checkpoint_manager_cls() -> Any:
    from src.core.checkpoint.manager import CheckpointManager

    return CheckpointManager


def attempt_recovery(*args: Any, **kwargs: Any) -> Any:
    from src.core.checkpoint.recovery import attempt_recovery as _attempt

    return _attempt(*args, **kwargs)


__all__ = ["file_checkpoint_cls", "attempt_recovery", "checkpoint_manager_cls"]
