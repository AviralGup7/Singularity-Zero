"""Checkpoint package – public re-exports.

All names previously importable from ``src.core.checkpoint`` are re-exported
here so existing import statements continue to work without modification.
"""

from src.core.checkpoint.base import (
    CheckpointIntegrityError,
    CheckpointState,
    _compute_checksum,
    _deserialize_sets,
    _serialize_sets,
)
from src.core.checkpoint.recovery import (
    _validate_checkpoint_state,
    attempt_recovery,
    generate_run_id,
)
from src.core.checkpoint.strategies import (
    CheckpointManager,
    StageCheckpointGuard,
    create_checkpoint_manager,
)

__all__ = [
    "CheckpointIntegrityError",
    "CheckpointManager",
    "CheckpointState",
    "StageCheckpointGuard",
    "_compute_checksum",
    "_deserialize_sets",
    "_serialize_sets",
    "_validate_checkpoint_state",
    "attempt_recovery",
    "create_checkpoint_manager",
    "generate_run_id",
]
