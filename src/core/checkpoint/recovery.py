"""Checkpoint recovery and run identification utilities."""

from __future__ import annotations

from typing import Any

from src.core.checkpoint.base import CheckpointState
from src.core.checkpoint.health import RecoveryCandidate, select_recovery_candidate
from src.core.checkpoint_recovery import (
    generate_run_id_impl,
    validate_checkpoint_state_impl,
)
from src.core.logging.trace_logging import get_pipeline_logger

_RECOVERY_STALE_AFTER_SECONDS = 3600.0

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


def verify_checkpoint_against_fsm(state: CheckpointState, authoritative_fsm: Any) -> bool:
    """Verify that a checkpoint projection is consistent with the authoritative Raft FSM.

    Enforces Axiom 1 and INVARIANT-007: Checkpoints are materialized read projections
    and may never override or contradict the authoritative Raft FSM state.
    """
    if authoritative_fsm is None:
        return True
    
    fsm_applied_index = getattr(authoritative_fsm, "last_applied_index", 0)
    chk_log_index = getattr(state, "authoritative_log_index", 0)
    
    # Checkpoint claiming a future log index that the FSM has not applied is invalid
    if chk_log_index > fsm_applied_index:
        logger.warning(
            "Checkpoint index %d is ahead of authoritative FSM index %d – rejected",
            chk_log_index,
            fsm_applied_index,
        )
        return False

    # If state hash is present, check against FSM state hash
    chk_state_hash = getattr(state, "authoritative_state_hash", "")
    if chk_state_hash and hasattr(authoritative_fsm, "get_state_hash"):
        fsm_state_hash = authoritative_fsm.get_state_hash()
        if chk_log_index == fsm_applied_index and fsm_state_hash and chk_state_hash != fsm_state_hash:
            logger.warning(
                "Checkpoint state hash mismatch at index %d: %s != FSM %s – rejected",
                chk_log_index,
                chk_state_hash,
                fsm_state_hash,
            )
            return False

    return True


def attempt_recovery(
    output_dir: Any,
    target_name: str,
    force_fresh: bool = False,
    storage_config: dict[str, Any] | None = None,
    local_node_id: str = "",
    authoritative_fsm: Any | None = None,
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

    # Scored candidates: fewest failures, then most completed stages,
    # then newest timestamp. Local-vs-remote fencing is applied below.
    candidates: list[RecoveryCandidate] = []
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
        if not verify_checkpoint_against_fsm(state, authoritative_fsm):
            logger.warning("Skipping checkpoint inconsistent with FSM: run=%s", run_id)
            continue
        completed_count = len(state.completed_stages) if hasattr(state, "completed_stages") else 0
        failed_count = _count_failed_stages(state)
        source = getattr(state, "source_node", "") or ""
        candidates.append(
            RecoveryCandidate(
                failed_neg=-failed_count,
                completed=completed_count,
                timestamp=float(getattr(state, "last_checkpoint_at", 0.0) or 0.0),
                source_node=source,
                state=state,
            )
        )

    if not candidates:
        return False, None

    chosen = select_recovery_candidate(
        candidates,
        local_node_id=local_node_id,
        stale_after_seconds=_RECOVERY_STALE_AFTER_SECONDS,
    )
    if chosen is None:
        return False, None

    best_state = chosen.state
    if chosen.failed_neg < 0:
        logger.warning(
            "Recovery selected checkpoint with %d failed stage(s) – no clean candidate available",
            -chosen.failed_neg,
        )

    if (
        local_node_id
        and chosen.source_node
        and chosen.source_node != local_node_id
        and chosen.stale
    ):
        logger.warning(
            "Recovery: remote checkpoint from %s is stale; local candidate preferred when present",
            chosen.source_node,
        )
    elif local_node_id and chosen.source_node == local_node_id:
        logger.info(
            "Recovery fencing: using local checkpoint (stages=%d source=%s)",
            chosen.completed,
            chosen.source_node,
        )

    has_incomplete = best_state.current_stage is not None or len(best_state.completed_stages) > 0
    return has_incomplete, best_state
