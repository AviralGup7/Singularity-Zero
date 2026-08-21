"""Checkpoint / WAL replay facade over core.checkpoint."""

from __future__ import annotations

from typing import Any


def checkpoint_manager_cls() -> Any:
    from src.core.checkpoint.manager import CheckpointManager

    return CheckpointManager


def attempt_recovery(*args: Any, **kwargs: Any) -> Any:
    from src.core.checkpoint.recovery import attempt_recovery as _attempt

    return _attempt(*args, **kwargs)


__all__ = ["attempt_recovery", "checkpoint_manager_cls"]
