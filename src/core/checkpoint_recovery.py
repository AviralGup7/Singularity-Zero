"""Recovery helpers extracted from the checkpoint module."""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any


def generate_run_id_impl() -> str:
    """Generate a unique run ID using timestamp + random suffix."""
    timestamp = int(time.time())
    suffix = uuid.uuid4().hex[:8]
    return f"run-{timestamp}-{suffix}"


def validate_checkpoint_state_impl(state: Any, *, checkpoint_state_cls: type[Any]) -> bool:
    """Validate checkpoint state shape before selecting it for recovery."""
    if not isinstance(state, checkpoint_state_cls):
        return False
    if not state.pipeline_run_id:
        return False
    if not isinstance(state.completed_stages, (list, set)):
        return False
    if isinstance(state.checkpoint_version, int) and state.checkpoint_version < 1:
        return False
    if state.started_at and state.started_at < 0:
        return False
    return True


def create_checkpoint_manager_impl(
    output_dir: Path,
    target_name: str,
    run_id: str | None,
    *,
    manager_cls: type[Any],
    generate_run_id_func: Any,
) -> Any:
    """Create a checkpoint manager with the standard target-scoped layout."""
    resolved_run_id = run_id or generate_run_id_func()
    checkpoint_dir = Path(output_dir) / target_name / "checkpoints"
    return manager_cls(checkpoint_dir, resolved_run_id)


def attempt_recovery_impl(
    output_dir: Path,
    target_name: str,
    *,
    force_fresh: bool,
    manager_cls: type[Any],
    validate_checkpoint_state_func: Any,
    logger_obj: Any,
) -> tuple[bool, Any | None]:
    """Scan run directories and choose the best recoverable checkpoint state."""
    if force_fresh:
        logger_obj.info("Fresh run forced (--force-fresh-run), skipping recovery")
        return False, None

    checkpoints_root = Path(output_dir) / target_name / "checkpoints"

    if not checkpoints_root.is_dir():
        return False, None

    candidates: list[tuple[int, float, Any]] = []

    for run_dir in sorted(checkpoints_root.iterdir()):
        if not run_dir.is_dir():
            continue

        run_id = run_dir.name
        manager = manager_cls(checkpoints_root, run_id)
        state = manager.load()

        if state is None:
            continue

        if not validate_checkpoint_state_func(state):
            logger_obj.warning("Skipping corrupted checkpoint: run=%s", run_id)
            continue

        completed_count = len(state.completed_stages) if hasattr(state, "completed_stages") else 0
        candidates.append((completed_count, state.last_checkpoint_at, state))

    if not candidates:
        return False, None

    candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)
    best_state = candidates[0][2]

    has_incomplete = best_state.current_stage is not None or len(best_state.completed_stages) > 0
    return has_incomplete, best_state


def load_context_snapshot_for_stage_impl(manager: Any, stage_name: str) -> dict[str, Any] | None:
    """Load context snapshot payload for a specific stage from current or legacy paths."""
    run_scoped_path = manager._context_snapshot_path(stage_name)
    legacy_path = manager.checkpoint_dir / f"{stage_name}.json"
    candidate_paths = [run_scoped_path, legacy_path]
    for path in candidate_paths:
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except OSError, json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            if "context" in payload and isinstance(payload["context"], dict):
                return payload["context"]
            if "scope_entries" in payload and "stage_status" in payload:
                return payload
    return None


def load_latest_context_snapshot_impl(
    manager: Any,
    completed_stages: list[str] | set[str] | None = None,
) -> dict[str, Any] | None:
    """Load newest context snapshot, preferring the latest completed stage payload."""
    if completed_stages:
        ordered_stages = [str(stage) for stage in completed_stages if str(stage).strip()]
        for stage_name in reversed(ordered_stages):
            snapshot = load_context_snapshot_for_stage_impl(manager, stage_name)
            if snapshot is not None:
                return snapshot

    if not manager._run_dir.exists():
        return None
    context_files = sorted(
        manager._run_dir.glob("context_*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for path in context_files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except OSError, json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and isinstance(payload.get("context"), dict):
            from typing import cast

            return cast(dict[str, Any], payload["context"])
    return None
