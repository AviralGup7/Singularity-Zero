"""Checkpoint recovery and run identification utilities."""

from __future__ import annotations

from typing import Any

from src.core.checkpoint.base import CheckpointState
from src.core.checkpoint_recovery import (
    generate_run_id_impl,
    validate_checkpoint_state_impl,
)
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


def generate_run_id() -> str:
    """Generate a unique run ID using timestamp + random suffix."""
    return generate_run_id_impl()


def _validate_checkpoint_state(state: CheckpointState) -> bool:
    """Validate that a checkpoint state has the expected structure.

    Catches corrupted or malformed checkpoints that would break recovery.
    """
    return validate_checkpoint_state_impl(state, checkpoint_state_cls=CheckpointState)


def attempt_recovery(
    output_dir: Any,
    target_name: str,
    force_fresh: bool = False,
    storage_config: dict[str, Any] | None = None,
) -> tuple[bool, CheckpointState | None]:
    """Scan for recoverable checkpoints across all runs for this target.

    Recovery prefers states with more completed stages (not just latest timestamp).
    Validates recovered state structure to avoid corrupting the pipeline.

    Args:
        output_dir: Base output directory.
        target_name: Target name.
        force_fresh: If True, skip recovery entirely.
        storage_config: Optional storage configuration for the backend.

    Returns:
        (can_recover, checkpoint_state).
    """
    from pathlib import Path

    from src.core.storage.factory import create_checkpoint_store

    if force_fresh:
        return False, None

    checkpoint_dir = Path(output_dir) / target_name / "checkpoints"
    store = create_checkpoint_store(storage_config, checkpoint_dir)

    candidates: list[tuple[int, float, CheckpointState]] = []
    for run_id in store.list_run_ids():
        payload = store.read_latest(run_id)
        if not payload:
            continue
        try:
            state = CheckpointState.from_dict(payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load checkpoint for run %s: %s", run_id, exc)
            continue
        if not _validate_checkpoint_state(state):
            logger.warning("Skipping corrupted checkpoint: run=%s", run_id)
            continue
        completed_count = len(state.completed_stages) if hasattr(state, "completed_stages") else 0
        candidates.append(
            (
                completed_count,
                float(getattr(state, "last_checkpoint_at", 0.0) or 0.0),
                state,
            )
        )

    if not candidates:
        return False, None

    candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)
    best_state = candidates[0][2]
    has_incomplete = best_state.current_stage is not None or len(best_state.completed_stages) > 0
    return has_incomplete, best_state
