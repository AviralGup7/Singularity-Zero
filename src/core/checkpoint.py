"""Stage-level checkpointing system for pipeline crash recovery.

Serializes execution state, progress markers, and intermediate results
to persistent storage, enabling automatic crash recovery and seamless
pipeline resumption from the last successful stage.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from src.core.checkpoint_recovery import (
    generate_run_id_impl,
    load_context_snapshot_for_stage_impl,
    load_latest_context_snapshot_impl,
    validate_checkpoint_state_impl,
)
from src.core.storage import CheckpointStore
from src.core.storage.factory import create_checkpoint_store

if TYPE_CHECKING:
    from src.infrastructure.checkpoint import DistributedCheckpointStore

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

_CHECKPOINT_SET_FIELDS = frozenset({"completed_stages"})


@dataclass
class CheckpointState:
    """Serializable snapshot of pipeline execution state."""

    pipeline_run_id: str
    """Unique identifier for this pipeline run."""

    checkpoint_version: int = 1
    """Incremented on each checkpoint."""

    completed_stages: list[str] = field(default_factory=list)
    """Stage names that completed successfully."""

    current_stage: str | None = None
    """Stage currently executing (None if not started or finished)."""

    stage_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    """Per-stage serialized results."""

    module_metrics: dict[str, Any] = field(default_factory=dict)
    """Timing and status metrics."""

    started_at: float = field(default_factory=time.time)
    """Unix timestamp when the pipeline run started."""

    last_checkpoint_at: float = field(default_factory=time.time)
    """Unix timestamp of the last checkpoint save."""

    crash_recovery: bool = False
    """Whether this is a recovery run."""

    recovery_from: str | None = None
    """Run ID we're recovering from."""

    iterative_state: dict[str, Any] = field(default_factory=dict)
    """State for iterative analysis (finding keys, feedback URLs, etc.)."""

    nuclei_state: dict[str, Any] = field(default_factory=dict)
    """Nuclei scanning state (targets, findings, etc.)."""

    stage_deltas: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    """Incremental per-stage progress deltas for mid-stage resume."""

    def to_dict(self) -> dict[str, Any]:
        """Convert state to a JSON-serializable dictionary."""
        raw = asdict(self)
        return cast(dict[str, Any], _serialize_sets(raw))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CheckpointState:
        """Reconstruct a CheckpointState from a deserialized dictionary."""
        data.pop("checksum", None)
        restored = _deserialize_sets(data)
        return cls(**restored)


def _serialize_sets(obj: Any) -> Any:
    """Recursively convert sets to sorted lists for JSON serialization."""
    if isinstance(obj, set):
        return sorted(str(item) for item in obj)
    if isinstance(obj, dict):
        return {key: _serialize_sets(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_serialize_sets(item) for item in obj]
    return obj


def _deserialize_sets(obj: Any, path: str = "") -> Any:
    """Recursively restore sets from lists at known set-field paths."""
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else key
            if current_path in _CHECKPOINT_SET_FIELDS and isinstance(value, list):
                result[key] = set(value)
            else:
                result[key] = _deserialize_sets(value, current_path)
        return result
    if isinstance(obj, list):
        return [_deserialize_sets(item, path) for item in obj]
    return obj


def _compute_checksum(data: str) -> str:
    """Compute a SHA-256 checksum for the given string data."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class CheckpointManager:
    """Manages stage-level checkpointing for crash recovery."""

    def __init__(
        self,
        checkpoint_dir: Path,
        run_id: str,
        checkpoint_store: CheckpointStore | None = None,
        storage_config: dict[str, Any] | None = None,
        distributed_store: DistributedCheckpointStore | None = None,
    ) -> None:
        """
        Initialize checkpoint manager.

        Args:
            checkpoint_dir: Directory to store checkpoint files.
            run_id: Unique identifier for this pipeline run.
            storage_config: Optional storage configuration for the backend.
            distributed_store: Optional Redis-backed distributed store for replication.
        """
        self.checkpoint_dir = Path(checkpoint_dir)
        self.run_id = run_id
        self._run_dir = self.checkpoint_dir / run_id
        self._store: CheckpointStore = checkpoint_store or create_checkpoint_store(
            storage_config, self.checkpoint_dir
        )
        self._distributed: DistributedCheckpointStore | None = distributed_store
        self._state: CheckpointState | None = None

    def _ensure_run_dir(self) -> None:
        """Create the run-specific checkpoint directory if it does not exist."""
        self._run_dir.mkdir(parents=True, exist_ok=True)

    def _checkpoint_path(self, version: int) -> Path:
        """Return the file path for a given checkpoint version."""
        return self._run_dir / f"checkpoint_v{version}.json"

    def _context_snapshot_path(self, stage_name: str) -> Path:
        """Return the run-scoped context snapshot path for a completed stage."""
        safe_stage = str(stage_name or "").strip() or "unknown"
        return self._run_dir / f"context_{safe_stage}.json"

    def _stage_delta_path(self, stage_name: str, sequence: int) -> Path:
        """Return the run-scoped path for an incremental stage delta."""
        safe_stage = str(stage_name or "").strip() or "unknown"
        return self._run_dir / f"delta_{safe_stage}_{sequence:06d}.json"

    @staticmethod
    def _existing_stage_status(payload: Any) -> str:
        if not isinstance(payload, dict):
            return ""
        return str(payload.get("status", "")).strip().lower()

    @staticmethod
    def _ensure_completed_stages_list(state: CheckpointState) -> list[str]:
        completed = state.completed_stages
        if isinstance(completed, list):
            return completed
        normalized = sorted(str(item) for item in completed) if isinstance(completed, set) else []
        state.completed_stages = normalized
        return normalized

    def save(self, state: CheckpointState) -> Path:
        """
        Serialize and persist checkpoint state to disk.

        Uses atomic write (temp file + rename) to prevent corruption.
        Also replicates to distributed store if configured.
        Returns the path to the written checkpoint file.
        """
        self._ensure_run_dir()

        state.last_checkpoint_at = time.time()
        data = state.to_dict()
        data["checksum"] = ""

        json_str = json.dumps(data, indent=2, sort_keys=True)
        checksum = _compute_checksum(json_str)
        data["checksum"] = checksum

        json_str = json.dumps(data, indent=2, sort_keys=True)
        json_bytes = json_str.encode("utf-8")

        try:
            checkpoint_path = self._store.write(
                run_id=state.pipeline_run_id,
                version=state.checkpoint_version,
                payload=json.loads(json_bytes),
            )
            logger.info(
                "Checkpoint saved: run=%s version=%d path=%s",
                state.pipeline_run_id,
                state.checkpoint_version,
                checkpoint_path,
            )
        except Exception as exc:
            logger.error("Failed to write checkpoint: %s", exc)
            raise

        # Replicate to distributed store if available
        if self._distributed:

            def _rollback(exc: Exception | BaseException) -> None:
                logger.warning(
                    "Replication failed, rolling back local checkpoint %s: %s", checkpoint_path, exc
                )
                try:
                    Path(checkpoint_path).unlink(missing_ok=True)
                except OSError:
                    pass

            try:
                # Fix Audit #11 & #12: Use running loop and create_task
                try:
                    loop = asyncio.get_running_loop()
                    task = loop.create_task(self._distributed.save_checkpoint(state, self.run_id))

                    def _on_done(t: asyncio.Task[Any]) -> None:
                        if t.cancelled():
                            _rollback(asyncio.CancelledError("Task cancelled"))
                        elif t.exception():
                            _rollback(t.exception())  # type: ignore

                    task.add_done_callback(_on_done)
                except RuntimeError:
                    # Fix #331: Run synchronously if no loop, and rollback on failure
                    try:
                        # Cannot use asyncio.to_thread if there is no running loop,
                        # but we want to avoid asyncio.run() creating a new loop.
                        # Wait, if there is no running loop, we can just run the coroutine directly? No.
                        # Let's just create a new loop but close it properly, or dispatch to a background thread.
                        loop = asyncio.new_event_loop()
                        try:
                            loop.run_until_complete(
                                self._distributed.save_checkpoint(state, self.run_id)
                            )
                        finally:
                            loop.close()
                    except Exception as e:
                        _rollback(e)
                        raise
            except Exception as exc:
                _rollback(exc)

        self._state = state
        return Path(checkpoint_path)

    def load(self) -> CheckpointState | None:
        """
        Load the most recent checkpoint for this run.

        Returns None if no checkpoint exists.
        """
        return self.load_latest_for_run(self.run_id)

    def load_latest_for_run(self, run_id: str | None = None) -> CheckpointState | None:
        """Load the latest checkpoint, optionally for a different run_id."""
        target_run_id = run_id or self.run_id
        target_dir = self.checkpoint_dir / target_run_id

        if not target_dir.is_dir():
            payload = self._store.read_latest(target_run_id)
            if payload is None:
                return None
            return self._load_from_payload(payload)

        checkpoint_files = sorted(target_dir.glob("checkpoint_v*.json"))
        if not checkpoint_files:
            payload = self._store.read_latest(target_run_id)
            if payload is None:
                return None
            return self._load_from_payload(payload)

        latest_path = checkpoint_files[-1]
        return self._load_from_file(latest_path)

    def _load_from_payload(self, data: dict[str, Any]) -> CheckpointState | None:
        """Load and validate a checkpoint from a payload dictionary."""
        payload = dict(data)

        stored_checksum = payload.pop("checksum", None)
        if stored_checksum is not None:
            data_for_check = dict(payload)
            data_for_check["checksum"] = ""
            check_str = json.dumps(data_for_check, indent=2, sort_keys=True)
            computed = _compute_checksum(check_str)
            if computed != stored_checksum:
                logger.warning(
                    "Checkpoint integrity check failed: expected=%s got=%s",
                    stored_checksum,
                    computed,
                )
                return None

        try:
            return CheckpointState.from_dict(payload)
        except (TypeError, KeyError) as exc:
            logger.error("Failed to reconstruct checkpoint state: %s", exc)
            return None

    def _load_from_file(self, path: str | Path) -> CheckpointState | None:
        """Load and validate a checkpoint from a specific file."""
        try:
            data = self._store.read_version(path)
            if not data:
                return None
        except Exception as exc:
            logger.error("Failed to read checkpoint file %s: %s", path, exc)
            return None

        return self._load_from_payload(data)

    def mark_stage_complete(self, stage_name: str, result: dict[str, Any]) -> None:
        """
        Mark a stage as completed and persist immediately.

        Updates the in-memory state and saves to disk.
        """
        payload = dict(result)
        payload.setdefault("status", "completed")
        self.mark_stage_outcome(stage_name, "completed", result=payload)

    def mark_stage_failed(self, stage_name: str, error: str) -> None:
        """Mark a stage as failed with error details."""
        self.mark_stage_outcome(
            stage_name,
            "failed",
            error=error,
            result={
                "status": "failed",
                "error": error,
            },
        )

    def mark_stage_outcome(
        self,
        stage_name: str,
        status: str,
        *,
        error: str = "",
        result: dict[str, Any] | None = None,
    ) -> None:
        """Persist an explicit stage outcome.

        This is used by the orchestrator after each stage finishes so
        checkpoint truth stays aligned with actual runtime status instead
        of inferring success from context-manager exit semantics.
        """
        current = self.ensure_state()
        current.checkpoint_version += 1

        normalized_status = str(status or "").strip().lower()
        if normalized_status in {"error", "failed", "timeout"}:
            normalized_status = "failed"
        elif normalized_status in {"skip", "skipped"}:
            normalized_status = "skipped"
        else:
            normalized_status = "completed"

        payload = dict(result or {})
        payload.setdefault("status", normalized_status)
        if error and "error" not in payload:
            payload["error"] = error

        completed_stages = self._ensure_completed_stages_list(current)
        if normalized_status in {"completed", "skipped"}:
            if stage_name not in completed_stages:
                completed_stages.append(stage_name)
        else:
            if stage_name in completed_stages:
                completed_stages.remove(stage_name)

        current.stage_results[stage_name] = payload
        current.current_stage = None
        self.save(current)

    def save_context_snapshot(self, stage_name: str, context_snapshot: dict[str, Any]) -> Path:
        """Persist a run-scoped full context snapshot for stage recovery."""
        self._ensure_run_dir()
        payload = {
            "pipeline_run_id": self.run_id,
            "stage_name": stage_name,
            "saved_at": time.time(),
            "context": context_snapshot,
        }
        target = self._context_snapshot_path(stage_name)
        temp = target.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, default=str), encoding="utf-8")
        temp.replace(target)
        return target

    def save_stage_delta(
        self,
        stage_name: str,
        delta: dict[str, Any],
        *,
        cursor: Any | None = None,
        delta_id: str | None = None,
        complete: bool = False,
    ) -> Path:
        """Persist an incremental delta for a long-running stage.

        Deltas are intentionally generic. Stages may store a resumable cursor
        plus a ``state_delta`` or ``context_delta`` payload; recovery replays
        those deltas after the last full context snapshot.
        """
        self._ensure_run_dir()
        current = self.ensure_state()
        deltas = current.stage_deltas.setdefault(stage_name, [])
        sequence = len(deltas) + 1
        target = self._stage_delta_path(stage_name, sequence)
        payload = {
            "pipeline_run_id": self.run_id,
            "stage_name": stage_name,
            "sequence": sequence,
            "delta_id": delta_id or f"{stage_name}:{sequence}",
            "cursor": _serialize_sets(cursor),
            "complete": bool(complete),
            "saved_at": time.time(),
            "delta": _serialize_sets(delta),
        }
        temp = target.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, default=str), encoding="utf-8")
        temp.replace(target)

        deltas.append(
            {
                "sequence": sequence,
                "delta_id": payload["delta_id"],
                "cursor": payload["cursor"],
                "complete": payload["complete"],
                "saved_at": payload["saved_at"],
                "path": str(target),
            }
        )
        current.current_stage = stage_name if not complete else current.current_stage
        current.checkpoint_version += 1
        self.save(current)
        return target

    def load_stage_deltas(self, stage_name: str) -> list[dict[str, Any]]:
        """Load all persisted deltas for a stage in sequence order."""
        if not self._run_dir.exists():
            return []
        safe_stage = str(stage_name or "").strip() or "unknown"
        payloads: list[dict[str, Any]] = []
        for path in sorted(self._run_dir.glob(f"delta_{safe_stage}_*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to read stage delta %s: %s", path, exc)
                continue
            if isinstance(payload, dict):
                payloads.append(payload)
        payloads.sort(key=lambda item: int(item.get("sequence", 0) or 0))
        return payloads

    def load_latest_stage_delta(self, stage_name: str) -> dict[str, Any] | None:
        """Load the newest persisted delta for a stage."""
        deltas = self.load_stage_deltas(stage_name)
        return deltas[-1] if deltas else None

    @staticmethod
    def _merge_context_delta(context: dict[str, Any], delta_payload: dict[str, Any]) -> None:
        """Replay a serialized context/state delta into a context snapshot."""
        delta = delta_payload.get("delta")
        if not isinstance(delta, dict):
            return
        context_delta = delta.get("context_delta")
        state_delta = delta.get("state_delta")
        updates = context_delta if isinstance(context_delta, dict) else state_delta
        if not isinstance(updates, dict):
            return
        for key, value in updates.items():
            context[key] = value

    def apply_stage_deltas(
        self,
        context_snapshot: dict[str, Any],
        stage_name: str,
    ) -> dict[str, Any]:
        """Return a context snapshot with all deltas for ``stage_name`` replayed."""
        restored = dict(context_snapshot)
        for delta_payload in self.load_stage_deltas(stage_name):
            self._merge_context_delta(restored, delta_payload)
        return restored

    def _load_context_snapshot_for_stage(self, stage_name: str) -> dict[str, Any] | None:
        return load_context_snapshot_for_stage_impl(self, stage_name)

    def load_latest_context_snapshot(
        self,
        completed_stages: list[str] | set[str] | None = None,
        include_stage_deltas: bool = True,
    ) -> dict[str, Any] | None:
        """Load the newest full context snapshot for recovery.

        Preference order:
        1) Most recent completed stage in the provided completed stage list.
        2) Most recent run-scoped context file by mtime.
        3) Replay deltas for the current in-flight stage, when present.
        """
        snapshot = load_latest_context_snapshot_impl(self, completed_stages)
        if snapshot is None:
            return None

        if not include_stage_deltas:
            return snapshot

        state = self.load()
        current_stage = str(getattr(state, "current_stage", "") or "").strip() if state else ""
        if not current_stage:
            return snapshot
        return self.apply_stage_deltas(snapshot, current_stage)

    def ensure_state(self) -> CheckpointState:
        """Return the current in-memory state, creating one if needed."""
        if self._state is None:
            existing = self.load()
            if existing is not None:
                self._state = existing
            else:
                self._state = CheckpointState(
                    pipeline_run_id=self.run_id,
                    checkpoint_version=0,
                )
        return self._state

    def should_resume(self) -> tuple[bool, CheckpointState | None]:
        """
        Check if a previous checkpoint exists for recovery.

        Returns (should_resume, checkpoint_state).
        """
        state = self.load()
        if state is None:
            return False, None

        has_incomplete = state.current_stage is not None or len(state.completed_stages) > 0
        return has_incomplete, state

    def get_remaining_stages(self, all_stages: list[str]) -> list[str]:
        """
        Given the full stage order, return stages that haven't completed.

        Used to determine where to resume from.
        """
        current = self.ensure_state()
        completed = set(current.completed_stages)
        return [stage for stage in all_stages if stage not in completed]

    def cleanup_old_checkpoints(self, keep_last: int = 3) -> int:
        """
        Remove old checkpoint files, keeping the most recent N.

        Returns the number of files deleted.
        """
        checkpoint_files = self._store.list_versions(self.run_id)
        if len(checkpoint_files) <= keep_last:
            return 0

        to_delete = checkpoint_files[:-keep_last]
        deleted = 0
        for path in to_delete:
            try:
                self._store.delete(path)
                deleted += 1
                logger.debug("Deleted old checkpoint: %s", path)
            except Exception as exc:
                logger.warning("Failed to delete checkpoint %s: %s", path, exc)
        return deleted

    def get_checkpoint_history(self) -> list[dict[str, Any]]:
        """
        List all checkpoint files for this run with metadata.

        Returns list of dicts with: version, timestamp, completed_stages, current_stage
        """
        checkpoint_files = self._store.list_versions(self.run_id)
        history: list[dict[str, Any]] = []

        for path in checkpoint_files:
            state = self._load_from_file(path)
            if state is None:
                continue
            history.append(
                {
                    "version": state.checkpoint_version,
                    "timestamp": state.last_checkpoint_at,
                    "completed_stages": list(state.completed_stages),
                    "current_stage": state.current_stage,
                    "file": str(path),
                }
            )

        return history


class StageCheckpointGuard:
    """Context manager for automatic stage checkpointing."""

    def __init__(self, manager: CheckpointManager, stage_name: str) -> None:
        """
        Initialize the guard.

        Args:
            manager: The CheckpointManager to use.
            stage_name: Name of the stage being executed.
        """
        self.manager = manager
        self.stage_name = stage_name
        self._start_time: float | None = None

    def __enter__(self) -> CheckpointManager:
        """Mark stage as starting."""
        self._start_time = time.time()
        current = self.manager.ensure_state()
        current.current_stage = self.stage_name
        current.module_metrics[f"{self.stage_name}_started_at"] = self._start_time
        self.manager.save(current)
        logger.info("Stage started: %s", self.stage_name)
        return self.manager

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Mark stage as completed or failed. Returns None to not suppress exceptions."""
        elapsed = time.time() - self._start_time if self._start_time else 0

        if exc_type is not None:
            error_msg = f"{exc_type.__name__}: {exc_val}"
            self.manager.mark_stage_outcome(
                self.stage_name,
                "failed",
                error=error_msg,
                result={
                    "status": "failed",
                    "error": error_msg,
                    "elapsed_seconds": elapsed,
                },
            )
            logger.error("Stage failed: %s (%s)", self.stage_name, error_msg)
            return None

        current = self.manager.ensure_state()
        existing_status = self.manager._existing_stage_status(
            current.stage_results.get(self.stage_name)
        )
        if existing_status in {"completed", "failed", "skipped"}:
            if current.current_stage is not None:
                current.current_stage = None
                self.manager.save(current)
            logger.info("Stage finalized: %s (%s)", self.stage_name, existing_status)
            return None

        self.manager.mark_stage_outcome(
            self.stage_name,
            "completed",
            result={
                "status": "completed",
                "elapsed_seconds": elapsed,
            },
        )
        logger.info("Stage completed: %s (%.2fs)", self.stage_name, elapsed)

        return None


def create_checkpoint_manager(
    output_dir: Path,
    target_name: str,
    run_id: str | None = None,
    storage_config: dict[str, Any] | None = None,
    distributed_store: DistributedCheckpointStore | None = None,
) -> CheckpointManager:
    """
    Create a CheckpointManager with standard directory layout.

    Args:
        output_dir: Base output directory for the pipeline.
        target_name: Name of the scan target (used for subdirectory).
        run_id: Optional run ID; generated if not provided.
        storage_config: Optional storage configuration for the backend.
        distributed_store: Optional Redis-backed store for replication.

    Returns:
        Configured CheckpointManager instance.
    """
    resolved_run_id = run_id or generate_run_id()
    checkpoint_dir = Path(output_dir) / target_name / "checkpoints"
    return CheckpointManager(
        checkpoint_dir,
        resolved_run_id,
        storage_config=storage_config,
        distributed_store=distributed_store,
    )


def attempt_recovery(
    output_dir: Path,
    target_name: str,
    force_fresh: bool = False,
    storage_config: dict[str, Any] | None = None,
) -> tuple[bool, CheckpointState | None]:
    """
    Scan for recoverable checkpoints across all runs for this target.

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
    except Exception as exc:
        logger.warning("Failed to recover checkpoint: %s", exc)

    return False, None


def _validate_checkpoint_state(state: CheckpointState) -> bool:
    """Validate that a checkpoint state has the expected structure.

    Catches corrupted or malformed checkpoints that would break recovery.
    """
    return validate_checkpoint_state_impl(state, checkpoint_state_cls=CheckpointState)


def generate_run_id() -> str:
    """Generate a unique run ID using timestamp + random suffix."""
    return generate_run_id_impl()
