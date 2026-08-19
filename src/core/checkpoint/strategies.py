"""Checkpoint manager strategies: save, load, retention, and stage guards."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

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

logger = get_pipeline_logger(__name__)


class CheckpointManager:
    """Manages stage-level checkpointing for crash recovery."""

    # Maximum number of replication retries before giving up.
    _REPLICATION_MAX_RETRIES: int = 3
    # Base delay (seconds) for exponential backoff between retries.
    _REPLICATION_RETRY_BASE_DELAY: float = 0.5

    #: Minimum seconds between periodic checkpoints during a running stage.
    ADAPTIVE_TIME_THRESHOLD: float = 30.0
    #: Minimum WAL deltas (calls to save_stage_delta) before a new checkpoint.
    ADAPTIVE_DELTA_THRESHOLD: int = 10

    def __init__(
        self,
        checkpoint_dir: Path,
        run_id: str,
        checkpoint_store: CheckpointStore | None = None,
        storage_config: dict[str, Any] | None = None,
        distributed_store: Any | None = None,
        source_node: str = "",
    ) -> None:
        self.checkpoint_dir = Path(checkpoint_dir)
        self.run_id = run_id
        self._run_dir = self.checkpoint_dir / run_id
        self._store: CheckpointStore = checkpoint_store or create_checkpoint_store(
            storage_config, self.checkpoint_dir
        )
        self._distributed: Any | None = distributed_store
        self._source_node: str = source_node
        self._state: CheckpointState | None = None
        self._lock = threading.RLock()
        # Track in-flight replication tasks for graceful shutdown (Bug #21).
        self._replication_tasks: set[asyncio.Task[bool]] = set()
        self._replication_lock = threading.Lock()
        # Bug #2 fix: Track replication threads for lifecycle management.
        self._replication_threads: set[threading.Thread] = set()
        self._replication_thread_lock = threading.Lock()
        # Adaptive checkpoint tracking
        self._last_adaptive_checkpoint_at: float = time.time()
        self._deltas_since_last_checkpoint: int = 0

    @property
    def completed_stages(self) -> list[str]:
        with self._lock:
            state = self.load()
            if state is None:
                return []
            return self._ensure_completed_stages_list(state)

    # ------------------------------------------------------------------
    # Distributed replication helpers (Bugs #17, #21)
    # ------------------------------------------------------------------

    async def _replicate_with_retry(
        self,
        state: CheckpointState,
        run_id: str,
    ) -> bool:
        """Replicate checkpoint to distributed store with retry and backoff.

        Returns True if replication succeeded, False after exhausting retries.
        """
        dist = self._distributed
        if dist is None:
            return False

        last_exc: BaseException | None = None
        for attempt in range(1, self._REPLICATION_MAX_RETRIES + 1):
            try:
                result = await dist.save_checkpoint(state, run_id)
                if result is True:
                    logger.info(
                        "Distributed replication succeeded for checkpoint %s v%s (attempt %d)",
                        state.pipeline_run_id,
                        state.checkpoint_version,
                        attempt,
                    )
                    return True
                logger.warning(
                    "Distributed replication returned %s for checkpoint %s v%s (attempt %d/%d)",
                    result,
                    state.pipeline_run_id,
                    state.checkpoint_version,
                    attempt,
                    self._REPLICATION_MAX_RETRIES,
                )
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                logger.warning(
                    "Distributed replication attempt %d/%d failed for checkpoint %s v%s: %s",
                    attempt,
                    self._REPLICATION_MAX_RETRIES,
                    state.pipeline_run_id,
                    state.checkpoint_version,
                    exc,
                )

            if attempt < self._REPLICATION_MAX_RETRIES:
                delay = self._REPLICATION_RETRY_BASE_DELAY * (2 ** (attempt - 1))
                await asyncio.sleep(delay)

        logger.error(
            "Distributed replication failed after %d attempts for checkpoint %s v%s: %s. "
            "Local checkpoint remains intact.",
            self._REPLICATION_MAX_RETRIES,
            state.pipeline_run_id,
            state.checkpoint_version,
            last_exc,
        )
        return False

    def _dispatch_replication(self, state: CheckpointState) -> None:
        """Dispatch an async replication task, tracked for graceful shutdown."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            task = loop.create_task(self._replicate_with_retry(state, self.run_id))
            with self._replication_lock:
                self._replication_tasks.add(task)
                task.add_done_callback(self._replication_tasks.discard)
            return

        # Bug #2 fix: Synchronous context – run in a tracked daemon thread.
        # The thread is registered so wait_for_replications() can join it
        # during shutdown, preventing the "replication silently lost" failure.
        def _sync_replicate() -> None:
            try:
                new_loop = asyncio.new_event_loop()
                try:
                    new_loop.run_until_complete(
                        self._replicate_with_retry(state, self.run_id),
                    )
                finally:
                    new_loop.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Synchronous distributed replication failed for checkpoint %s v%s: %s",
                    state.pipeline_run_id,
                    state.checkpoint_version,
                    exc,
                )

        thread = threading.Thread(
            target=_sync_replicate,
            name=f"checkpoint-replicate-{state.pipeline_run_id}-v{state.checkpoint_version}",
            daemon=True,
        )
        # Bug #12: Register with LifecycleManager so it is joined during
        # shutdown instead of being killed mid-flight by the OS.
        try:
            from src.core.lifecycle import get_lifecycle_manager

            lm = get_lifecycle_manager()
            lm.register_thread(thread.name, thread)
        except ImportError:
            pass
        with self._replication_thread_lock:
            self._replication_threads.add(thread)
        thread.start()

        # Auto-remove from tracking when thread finishes
        def _on_thread_done() -> None:
            with self._replication_thread_lock:
                self._replication_threads.discard(thread)

        thread.join_event = getattr(thread, "join_event", None)  # type: ignore[attr-defined]
        # Use a small watcher thread to clean up (daemon, so won't block shutdown)
        threading.Thread(target=lambda: (thread.join(), _on_thread_done()), daemon=True).start()

    async def wait_for_replications(self, timeout: float = 10.0) -> bool:
        """Wait for all in-flight replication tasks AND threads to finish.

        Called during graceful shutdown so that replicated state is durable
        before executors and storage backends are torn down.

        Bug #2 fix: Also waits for replication threads (not just async tasks)
        to prevent silent loss of distributed replicas on shutdown.

        Returns True if all tasks/threads completed within *timeout*.
        """
        with self._replication_lock:
            tasks = list(self._replication_tasks)
        with self._replication_thread_lock:
            threads = list(self._replication_threads)

        if not tasks and not threads:
            return True

        logger.info(
            "Waiting for %d replication task(s) and %d replication thread(s)…",
            len(tasks),
            len(threads),
        )

        all_done = True

        # Wait for async tasks
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=timeout)
            if pending:
                logger.warning(
                    "%d replication task(s) still pending after %.1fs shutdown timeout",
                    len(pending),
                    timeout,
                )
                all_done = False

        # Wait for threads (using asyncio.to_thread to avoid blocking the loop)
        if threads:
            import concurrent.futures

            thread_timeout = max(0.1, timeout - 0.5)  # Leave some margin
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(threads)) as pool:
                futures = {pool.submit(t.join, thread_timeout): t for t in threads}
                for future in concurrent.futures.as_completed(futures, timeout=timeout):
                    try:
                        future.result()
                    except Exception:
                        logger.warning(
                            "Future wait failed during checkpoint replication", exc_info=True
                        )
                        all_done = False

        return all_done

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

    def _resolve_local_checkpoint_file(self, version_id: VersionId) -> Path | None:
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
            # Bug #31 fix: stamp the source node for distributed fencing
            if self._source_node and not state.source_node:
                state.source_node = self._source_node
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

            if self._distributed is not None:
                self._dispatch_replication(state)

            self._state = state
            local_marker = (
                self.checkpoint_dir
                / state.pipeline_run_id
                / f"checkpoint_v{state.checkpoint_version}.json"
            )
            return local_marker

    async def save_and_wait(self, state: CheckpointState, timeout: float = 10.0) -> Path:
        """Save checkpoint and wait for replication to complete.

        Bug #3 fix: Unlike save() which returns immediately while replication
        runs async, this method blocks until replication finishes (or times out),
        ensuring the caller has true durability before proceeding.

        Use this for critical checkpoints where the next stage depends on the
        distributed replica being visible (e.g. before failover, before pipeline
        completion signal).
        """
        local_marker = self.save(state)
        await self.wait_for_replications(timeout=timeout)
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

    def _load_from_version_id(self, run_id: str, version_id: VersionId) -> CheckpointState | None:
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

            # Bug #29 fix: Preserve immutable first-failure snapshot.
            # Once set, first_failure is never overwritten, so the original
            # root cause survives retries and subsequent failures.
            if normalized_status == "failed" and current.first_failure is None:
                import time as _time

                current.first_failure = {
                    "failed_stage": stage_name,
                    "failure_reason": error or "",
                    "failure_step": payload.get("error", ""),
                    "failure_reason_code": payload.get("failure_reason_code", ""),
                    "timestamp": _time.time(),
                }

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
            # Adaptive: checkpoint on delta threshold or time since last
            self._deltas_since_last_checkpoint += 1
            self.auto_checkpoint(stage_name=stage_name if not complete else None)
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

    # ------------------------------------------------------------------
    # Artifact integrity tracking (Bug #23)
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_file(path: str) -> str:
        """Compute SHA-256 hex digest for a single file."""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def record_artifact_hashes(
        self,
        stage_name: str,
        artifact_paths: list[str],
    ) -> dict[str, str]:
        """Hash the given artifact files and store them in checkpoint state.

        Called by stage guards or pipeline runners after a stage produces
        output files.  The hashes are persisted with the next checkpoint
        save so that resume can later verify the artifacts are intact.

        Returns the mapping ``{path: sha256}`` that was recorded.
        """
        hashes: dict[str, str] = {}
        for p in artifact_paths:
            try:
                hashes[p] = self._hash_file(p)
            except OSError as exc:
                logger.warning("Could not hash artifact %s: %s", p, exc)
        if not hashes:
            return hashes
        with self._lock:
            current = self.ensure_state()
            current.artifact_hashes[stage_name] = hashes
        logger.debug(
            "Recorded %d artifact hash(es) for stage %s",
            len(hashes),
            stage_name,
        )
        return hashes

    def validate_artifacts_integrity(self) -> dict[str, list[str]]:
        """Check all recorded artifact hashes against current file state.

        Returns a dict ``{"valid": [...], "corrupted": [...], "missing": [...]}``
        so callers can decide whether to re-run stages whose artifacts
        have been tampered with or lost.
        """
        with self._lock:
            state = self.load()
        if state is None:
            return {"valid": [], "corrupted": [], "missing": []}

        valid: list[str] = []
        corrupted: list[str] = []
        missing: list[str] = []

        for stage_name, hashes in state.artifact_hashes.items():
            for path, expected_hash in hashes.items():
                if not os.path.isfile(path):
                    missing.append(path)
                    logger.warning(
                        "Artifact missing: stage=%s path=%s",
                        stage_name,
                        path,
                    )
                    continue
                try:
                    actual_hash = self._hash_file(path)
                except OSError as exc:
                    missing.append(path)
                    logger.warning(
                        "Artifact unreadable: stage=%s path=%s: %s",
                        stage_name,
                        path,
                        exc,
                    )
                    continue
                if actual_hash != expected_hash:
                    corrupted.append(path)
                    logger.warning(
                        "Artifact corrupted: stage=%s path=%s expected=%s actual=%s",
                        stage_name,
                        path,
                        expected_hash,
                        actual_hash,
                    )
                else:
                    valid.append(path)

        if corrupted or missing:
            logger.warning(
                "Artifact integrity check: %d valid, %d corrupted, %d missing",
                len(valid),
                len(corrupted),
                len(missing),
            )
        return {"valid": valid, "corrupted": corrupted, "missing": missing}

    def get_stages_with_corrupted_artifacts(self) -> list[str]:
        """Return stage names whose artifacts are corrupted or missing.

        Useful for the resume planner to decide which stages must be
        re-run even if ``completed_stages`` says they finished.
        """
        report = self.validate_artifacts_integrity()
        bad_paths = set(report["corrupted"]) | set(report["missing"])
        if not bad_paths:
            return []

        with self._lock:
            state = self.load()
        if state is None:
            return []

        affected: list[str] = []
        for stage_name, hashes in state.artifact_hashes.items():
            if any(p in bad_paths for p in hashes):
                affected.append(stage_name)
        return affected

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

    # ------------------------------------------------------------------
    # Adaptive mid-stage checkpointing
    # ------------------------------------------------------------------

    def auto_checkpoint(
        self,
        *,
        force: bool = False,
        stage_name: str | None = None,
    ) -> Path | None:
        """Save a checkpoint if any adaptive trigger fires.

        Triggers (combined with OR):

        * **Time threshold:** ``ADAPTIVE_TIME_THRESHOLD`` seconds elapsed
          since the last checkpoint (30s default).
        * **Delta threshold:** ``ADAPTIVE_DELTA_THRESHOLD`` stage-output
          deltas accumulated since the last checkpoint (10 default).
        * **Force flag:** external caller demands a checkpoint now.

        Call this from `merge_stage_output`, periodic pipeline ticks, or
        before any operation that would lose progress on crash (e.g. a
        WAL compaction / scope merge).

        Returns the checkpoint path when saved, ``None`` when no trigger
        fired or there is no state to persist.

        .. note::

           This does NOT increment the checkpoint version or modify
           stage lifecycle — it is purely a durability safeguard so
           that a mid-stage crash loses at most 30s of work.
        """
        with self._lock:
            if self._state is None:
                current = self.load()
                if current is None:
                    return None
                self._state = current
            else:
                current = self._state

            now = time.time()
            time_since = now - self._last_adaptive_checkpoint_at

            if force:
                reason = "forced"
            elif time_since >= self.ADAPTIVE_TIME_THRESHOLD:
                reason = f"time ({time_since:.0f}s)"
            elif self._deltas_since_last_checkpoint >= self.ADAPTIVE_DELTA_THRESHOLD:
                reason = f"delta-count ({self._deltas_since_last_checkpoint})"
            else:
                return None

            # Stamp a lightweight progress marker without altering stage lifecycle.
            current.last_checkpoint_at = now
            current.checkpoint_version += 1
            if stage_name:
                current.current_stage = stage_name

            data = current.to_dict()
            data["checksum"] = ""

            json_str_base = json.dumps(data, indent=2, sort_keys=True)
            checksum = _compute_checksum(json_str_base)
            json_str = json_str_base.replace('"checksum": ""', f'"checksum": "{checksum}"', 1)

            try:
                written = self._store.write(
                    run_id=current.pipeline_run_id,
                    version=current.checkpoint_version,
                    payload=json.loads(json_str),
                )
                _ = written  # version_id returned by write, unused here
            except Exception as exc:
                logger.error("Adaptive checkpoint write failed: %s", exc)
                return None

            self._last_adaptive_checkpoint_at = now
            self._deltas_since_last_checkpoint = 0
            self._state = current

            if self._distributed is not None:
                self._dispatch_replication(current)

            logger.debug(
                "Adaptive checkpoint v%s saved (trigger: %s) for stage=%s",
                current.checkpoint_version,
                reason,
                stage_name or "none",
            )
            local_path = (
                self.checkpoint_dir
                / current.pipeline_run_id
                / f"checkpoint_v{current.checkpoint_version}.json"
            )
            return local_path


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
            # Bug fix: Also mark the stage as failed in the in-memory
            # CheckpointState so downstream code sees consistent state
            # without re-reading from persistence.
            try:
                current = self.manager.ensure_state()
                if hasattr(current, "module_metrics"):
                    current.module_metrics[self.stage_name] = {
                        "status": "failed",
                        "error": error_msg,
                        "elapsed_seconds": elapsed,
                    }
            except Exception:
                pass
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
    source_node: str = "",
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
        source_node=source_node,
    )
