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


def _count_failed_stages(state: CheckpointState) -> int:
    """Count stages marked completed but with error/failed status in results.

    A stage may appear in ``completed_stages`` but have a ``failed`` or
    ``error`` entry in ``stage_results`` (e.g. partial corruption, a stage
    that was forcefully advanced past a failure).  These poisoned entries
    must penalise the candidate so that a cleaner run is preferred.
    """
    failed = 0
    for stage_name, result in state.stage_results.items():
        if not isinstance(result, dict):
            continue
        status = str(result.get("status", "")).strip().lower()
        if status in {"failed", "error", "timeout"}:
            failed += 1
    return failed


def attempt_recovery(
    output_dir: Any,
    target_name: str,
    force_fresh: bool = False,
    storage_config: dict[str, Any] | None = None,
    local_node_id: str = "",
) -> tuple[bool, CheckpointState | None]:
    """Scan for recoverable checkpoints across all runs for this target.

    Recovery scoring (highest wins):
      1. Fewest failed/error stages (clean runs preferred over
         "more complete but corrupted" runs – fixes Chain Bug #16).
      2. Most completed stages.
      3. Newest timestamp.

    Validates recovered state structure to avoid corrupting the pipeline.

    Bug #31 fix: When local_node_id is provided, recovery uses source-node
    fencing to avoid split-brain: if the best checkpoint came from a
    different node and a local checkpoint exists with comparable progress,
    prefer the local one to avoid replaying stale remote state.

    Args:
        output_dir: Base output directory.
        target_name: Target name.
        force_fresh: If True, skip recovery entirely.
        storage_config: Optional storage configuration for the backend.
        local_node_id: Identifier of the current node for fencing.

    Returns:
        (can_recover, checkpoint_state).
    """
    from pathlib import Path

    from src.core.storage.factory import create_checkpoint_store

    if force_fresh:
        return False, None

    checkpoint_dir = Path(output_dir) / target_name / "checkpoints"
    store = create_checkpoint_store(storage_config, checkpoint_dir)

    # Tuple: (failed_count_neg, completed_count, timestamp, source_node, state)
    #   failed_count_neg is negated so sorting DESC works correctly:
    #   fewer failures → higher value.
    candidates: list[tuple[int, int, float, str, CheckpointState]] = []
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
        failed_count = _count_failed_stages(state)
        source = getattr(state, "source_node", "") or ""
        candidates.append(
            (
                -failed_count,
                completed_count,
                float(getattr(state, "last_checkpoint_at", 0.0) or 0.0),
                source,
                state,
            )
        )

    if not candidates:
        return False, None

    candidates.sort(key=lambda c: (c[0], c[1], c[2]), reverse=True)
    best = candidates[0]
    best_state = best[4]
    best_source = best[3]

    if best[0] < 0:
        logger.warning(
            "Recovery selected checkpoint with %d failed stage(s) – "
            "no clean candidate available",
            -best[0],
        )

    # Bug #31 fencing: if the best checkpoint is from a remote node and
    # we have a local checkpoint, prefer the local one to avoid split-brain.
    if local_node_id and best_source and best_source != local_node_id:
        local_candidates = [c for c in candidates if c[3] == local_node_id]
        if local_candidates:
            local_best = local_candidates[0]
            # Accept local if it's within 5 stages of the remote best
            # (conservative: only fence if the remote is not significantly ahead)
            if local_best[1] >= best[1] - 5:
                logger.warning(
                    "Bug #31 fencing: preferring local checkpoint (stages=%d) "
                    "over remote checkpoint from node %s (stages=%d) "
                    "to avoid split-brain recovery",
                    local_best[1],
                    best_source,
                    best[1],
                )
                best_state = local_best[4]

    has_incomplete = best_state.current_stage is not None or len(best_state.completed_stages) > 0
    return has_incomplete, best_state
