"""Unified snapshot + journal recovery.

Checkpoint is the coarse snapshot. WAL is the incremental journal.
``RecoveryManager`` reconstructs pipeline state from both and hands
the result to DAG resume.
"""

from src.core.recovery.manager import (
    ReconstructedState,
    RecoveryManager,
    WalReplayMode,
)

__all__ = [
    "ReconstructedState",
    "RecoveryManager",
    "WalReplayMode",
]
