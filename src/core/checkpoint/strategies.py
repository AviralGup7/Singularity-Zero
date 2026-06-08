"""Checkpoint manager strategies: save, load, retention, and stage guards."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from src.core.checkpoint.base import (
    CheckpointIntegrityError,
    CheckpointState,
    _compute_checksum,
    _serialize_sets,
)
from src.core.checkpoint_recovery import (
    load_context_snapshot_for_stage_impl,
    load_latest_context_snapshot_impl,
)
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.storage import CheckpointStore, VersionId
from src.core.storage.factory import create_checkpoint_store

if TYPE_CHECKING:
    from src.infrastructure.checkpoint import DistributedCheckpointStore

logger = get_pipeline_logger(__name__)


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
        self.checkpoint_dir = Path(checkpoint_dir)
        self.run_id = run_id
        self._run_dir = self.checkpoint_dir / run_id
        self._store: CheckpointStore = checkpoint_store or create_checkpoint_store(
            storage_config, self.checkpoint_dir
        )
        self._distributed: DistributedCheckpointStore | None = distributed_store
        self._state: CheckpointState | None = None
        self._lock = threading.RLock()

    @property
    def completed_stages(self) -> list[str]:
        with self._lock:
            state = self.load()
            if state is None:
                return []
            return self._ensure_completed_stages_list(state)

    def _context_snapshot_path(self, stage_name: str) -> Path:
        from src.core.storage.local_backends import _stage_safe_name

        return self._run_dir / f"context_{_stage_safe_name(stage_name)}.json"

    def _stage_delta_path(self, stage_name: str, sequence: int) -> Path:
        from src.core.storage.local_backends import _stage_safe_name

        return self._run_dir / f"delta_{_stage_safe_name(stage_name)}_{sequence:06d}.json"

    def _checkpoint_path(self, version: int) -> Path:
        return self._run_dir / f"checkpoint_v{version}.json"

    def _ensure_run_dir(self) -> None:
        """Backwards-compat shim: ensure the run directory exists on disk.

        Modern runs write through the configured :class:`CheckpointStore`
        so this method is only meaningful for the local backend. We call
        it anyway so that callers (and tests) that pre-create the run
        directory still work on every backend.
        """
        self._run_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_local_checkpoint_file(
        self, version_id: VersionId
    ) -> Path | None:
        """Best-effort local file path for a given ``version_id``.

        Returns the local on-disk file when the store is a
        :class:`LocalCheckpointStore` (or wraps one) so that
        ``get_checkpoint_history`` can still surface a ``file`` key for
        dashboards and operators. Returns ``None`` for distributed
        backends where there is no local file to point at.
        """
        from src.core.storage.local_backends import LocalCheckpointStore

        store = self._store
        if isinstance(store, LocalCheckpointStore):
            return store._checkpoint_path(self.run_id, self._version_to_int(version_id))
        return None

    @staticmethod
    def _version_to_int(version_id: VersionId) -> int:
        from src.core.storage.local_backends import _parse_version_id

        return _parse_version_id(version_id)

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
        with self._lock:
            state.last_checkpoint_at = time.time()
            data = state.to_dict()
            data["checksum"] = ""

            json_str_base = json.dumps(data, indent=2, sort_keys=True)
            checksum = _compute_checksum(json_str_base)

            json_str = json_str_base.replace('"checksum": ""', f'"checksum": "{checksum}"', 1)
            json_bytes = json_str.encode("utf-8")

            try:
                version_id = self._store.write(
                    run_id=state.pipeline_run_id,
                    version=state.checkpoint_version,
                    payload=json.loads(json_bytes),
                )
                logger.info(
                    "Checkpoint saved: run=%s version=%d id=%s",
                    state.pipeline_run_id,
                    state.checkpoint_version,
                    version_id,
                )
            except Exception as exc:
                logger.error("Failed to write checkpoint: %s", exc)
                raise

            dist = self._distributed
            if dist is not None:

                def _log_replication_failure(exc: BaseException | None) -> None:
                    logger.warning(
                        "Distributed replication failed for checkpoint %s v%s: %s. "
                        "Local checkpoint remains intact.",
                        state.pipeline_run_id,
                        state.checkpoint_version,
                        exc,
                    )

                try:
                    try:
                        loop = asyncio.get_running_loop()
                        task = loop.create_task(dist.save_checkpoint(state, self.run_id))

                        def _on_done(t: asyncio.Task[Any]) -> None:
                            if t.cancelled():
                                _log_replication_failure(asyncio.CancelledError("Task cancelled"))
                            elif t.exception() is not None:
                                _log_replication_failure(t.exception())

                        task.add_done_callback(_on_done)
                    except RuntimeError:
                        try:
                            loop = asyncio.new_event_loop()
                            try:
                                loop.run_until_complete(dist.save_checkpoint(state, self.run_id))
                            finally:
                                try:
                                    loop.close()
                                except (RuntimeError, OSError) as loop_close_exc:
                                    _log_replication_failure(loop_close_exc)
                        except Exception as e:
                            _log_replication_failure(e)
                except Exception as exc:
                    _log_replication_failure(exc)

            self._state = state
            local_marker = self.checkpoint_dir / state.pipeline_run_id / f"checkpoint_v{state.checkpoint_version}.json"
            return local_marker

    def load(self) -> CheckpointState | None:
        with self._lock:
            try:
                return self.load_latest_for_run(self.run_id)
            except CheckpointIntegrityError:
                return None

    def load_latest_for_run(self, run_id: str | None = None) -> CheckpointState | None:
        with self._lock:
            try:
                target_run_id = run_id or self.run_id
                payload = self._store.read_latest(target_run_id)
                if payload is None:
                    return None
                return self._load_from_payload(payload)
            except CheckpointIntegrityError:
                return None

    def _load_from_payload(self, data: dict[str, Any]) -> CheckpointState | None:
        payload = dict(data)

        stored_checksum = payload.pop("checksum", None)
        if stored_checksum is not None:
            data_for_check = dict(payload)
            data_for_check["checksum"] = ""
            check_str = json.dumps(data_for_check, indent=2, sort_keys=True)
            computed = _compute_checksum(check_str)
            if computed != stored_checksum:
                logger.error(
                    "Checkpoint integrity check failed: expected=%s got=%s",
                    stored_checksum,
                    computed,
                )
                raise CheckpointIntegrityError(
                    f"Integrity check failed: expected={stored_checksum} got={computed}"
                )

        try:
            return CheckpointState.from_dict(payload)
        except (TypeError, KeyError) as exc:
            logger.error("Failed to reconstruct checkpoint state: %s", exc)
            return None

    def _load_from_version_id(
        self, run_id: str, version_id: VersionId
    ) -> CheckpointState | None:
        try:
            data = self._store.read_version_by_id(run_id, version_id)
        except Exception as exc:
            logger.error("Failed to read checkpoint %s/%s: %s", run_id, version_id, exc)
            return None
        if not data:
            return None
        return self._load_from_payload(data)

    def mark_stage_complete(self, stage_name: str, result: dict[str, Any]) -> None:
        payload = dict(result)
        payload.setdefault("status", "completed")
        self.mark_stage_outcome(stage_name, "completed", result=payload)

    def mark_stage_failed(self, stage_name: str, error: str) -> None:
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
        with self._lock:
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
        with self._lock:
            payload = {
                "pipeline_run_id": self.run_id,
                "stage_name": stage_name,
                "saved_at": time.time(),
                "context": context_snapshot,
            }
            self._store.write_context_snapshot(self.run_id, stage_name, payload)
            return self._context_snapshot_path(stage_name)

    def save_stage_delta(
        self,
        stage_name: str,
        delta: dict[str, Any],
        *,
        cursor: Any | None = None,
        delta_id: str | None = None,
        complete: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        with self._lock:
            current = self.ensure_state()
            deltas = current.stage_deltas.setdefault(stage_name, [])
            sequence = len(deltas) + 1
            payload: dict[str, Any] = {
                "pipeline_run_id": self.run_id,
                "stage_name": stage_name,
                "sequence": sequence,
                "delta_id": delta_id or f"{stage_name}:{sequence}",
                "cursor": _serialize_sets(cursor),
                "complete": bool(complete),
                "saved_at": time.time(),
                "delta": _serialize_sets(delta),
            }
            if metadata is not None:
                payload["metadata"] = dict(metadata)
            self._store.write_stage_delta(self.run_id, stage_name, sequence, payload)

            deltas.append(
                {
                    "sequence": sequence,
                    "delta_id": payload["delta_id"],
                    "cursor": payload["cursor"],
                    "complete": payload["complete"],
                    "saved_at": payload["saved_at"],
                }
            )
            current.current_stage = stage_name if not complete else current.current_stage
            current.checkpoint_version += 1
            self.save(current)
            return self._stage_delta_path(stage_name, sequence)

    def load_stage_deltas(self, stage_name: str) -> list[dict[str, Any]]:
        with self._lock:
            return self._store.list_stage_deltas(self.run_id, stage_name)

    def load_latest_stage_delta(self, stage_name: str) -> dict[str, Any] | None:
        with self._lock:
            deltas = self.load_stage_deltas(stage_name)
            return deltas[-1] if deltas else None

    @staticmethod
    def _merge_context_delta(context: dict[str, Any], delta_payload: dict[str, Any]) -> None:
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
        with self._lock:
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
        with self._lock:
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
        with self._lock:
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
        with self._lock:
            state = self.load()
            if state is None:
                return False, None

            has_incomplete = state.current_stage is not None or len(state.completed_stages) > 0
            return has_incomplete, state

    def get_remaining_stages(self, all_stages: list[str]) -> list[str]:
        with self._lock:
            current = self.ensure_state()
            completed = set(current.completed_stages)
            return [stage for stage in all_stages if stage not in completed]

    def cleanup_old_checkpoints(self, keep_last: int = 3) -> int:
        with self._lock:
            version_ids = self._store.list_version_ids(self.run_id)
            if len(version_ids) <= keep_last:
                return 0

            to_delete = version_ids[:-keep_last]
            deleted = 0
            for version_id in to_delete:
                try:
                    self._store.delete_version(self.run_id, version_id)
                    deleted += 1
                    logger.debug("Deleted old checkpoint: %s", version_id)
                except Exception as exc:
                    logger.warning("Failed to delete checkpoint %s: %s", version_id, exc)
            return deleted

    def get_checkpoint_history(self) -> list[dict[str, Any]]:
        with self._lock:
            history: list[dict[str, Any]] = []
            for version_id in self._store.list_version_ids(self.run_id):
                state = self._load_from_version_id(self.run_id, version_id)
                if state is None:
                    continue
                entry: dict[str, Any] = {
                    "version": state.checkpoint_version,
                    "timestamp": state.last_checkpoint_at,
                    "completed_stages": list(state.completed_stages),
                    "current_stage": state.current_stage,
                    "version_id": version_id,
                }
                local_file = self._resolve_local_checkpoint_file(version_id)
                if local_file is not None:
                    entry["file"] = str(local_file)
                history.append(entry)
            return history


class StageCheckpointGuard:
    """Context manager for automatic stage checkpointing."""

    def __init__(self, manager: CheckpointManager, stage_name: str) -> None:
        self.manager = manager
        self.stage_name = stage_name
        self._start_time: float | None = None

    def __enter__(self) -> CheckpointManager:
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
    distributed_store: Any | None = None,
) -> CheckpointManager:
    """Create a CheckpointManager with standard directory layout."""
    from src.core.checkpoint.recovery import generate_run_id

    resolved_run_id = run_id or generate_run_id()
    checkpoint_dir = Path(output_dir) / target_name / "checkpoints"
    return CheckpointManager(
        checkpoint_dir,
        resolved_run_id,
        storage_config=storage_config,
        distributed_store=distributed_store,
    )
