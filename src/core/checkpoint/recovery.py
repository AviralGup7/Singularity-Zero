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
    latest_payload = store.read_latest()
    if not latest_payload:
        return False, None

    try:
        state = CheckpointState.from_dict(latest_payload)
        if _validate_checkpoint_state(state):
            return True, state
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to recover checkpoint: %s", exc)

    return False, None
