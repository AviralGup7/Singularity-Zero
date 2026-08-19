"""Snapshot + journal recovery manager.

Hierarchy
---------
::

    Recovery Manager
           │
     ┌─────┴─────┐
     ▼           ▼
 Checkpoint     WAL
  Snapshot   Incremental
     │           │
     └─────┬─────┘
           ▼
    Reconstructed
        State
           │
           ▼
      DAG Resume

Checkpoint is the coarse baseline (completed stages, config, target,
major context). WAL is the fine-grained journal (frontier deltas,
discovered URLs, events since the last snapshot).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from src.core.checkpoint.base import CheckpointState
from src.core.checkpoint.recovery import attempt_recovery, generate_run_id
from src.core.checkpoint.strategies import create_checkpoint_manager
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class WalReplayMode(StrEnum):
    """How the WAL journal is applied on top of a checkpoint snapshot."""

    REPLAY = "replay"
    VERIFY = "verify"
    DRY_RUN = "dry-run"


@dataclass
class ReconstructedState:
    """State handed to DAG resume after snapshot + journal reconstruction."""

    run_id: str
    can_recover: bool
    source: str
    mode: WalReplayMode
    checkpoint: CheckpointState | None = None
    checkpoint_mgr: Any = None
    context_payload: dict[str, Any] | None = None
    completed_stages: set[str] = field(default_factory=set)
    remaining_stages: list[str] = field(default_factory=list)
    wal: Any = None
    wal_state: Any = None
    checkpoint_counts: dict[str, int] = field(default_factory=dict)
    wal_counts: dict[str, int] = field(default_factory=dict)
    verify_report: dict[str, Any] = field(default_factory=dict)
    execute_stages: bool = True


class RecoveryManager:
    """Load a checkpoint snapshot, replay the WAL journal, reconstruct state."""

    def __init__(
        self,
        output_dir: Path,
        target_name: str,
        *,
        redis_url: str | None = None,
        storage_config: dict[str, Any] | None = None,
        stage_order: list[str] | tuple[str, ...] = (),
        min_checkpoint_version: int = 2,
        wal_factory: Any | None = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.target_name = target_name
        self.redis_url = redis_url
        self.storage_config = storage_config
        self.stage_order = list(stage_order)
        self.min_checkpoint_version = min_checkpoint_version
        self._wal_factory = wal_factory

    def recover(
        self,
        *,
        force_fresh: bool = False,
        resume_from: str | None = None,
        wal_replay: str | WalReplayMode = WalReplayMode.REPLAY,
        pre_recovered_state: CheckpointState | None = None,
    ) -> ReconstructedState:
        """Return reconstructed state from checkpoint snapshot + WAL journal."""
        mode = self._coerce_mode(wal_replay)
        if force_fresh:
            return self._fresh(mode)

        checkpoint = pre_recovered_state
        if checkpoint is None:
            checkpoint = self._load_checkpoint_snapshot(resume_from)
        if checkpoint is None:
            return self._fresh(mode)

        run_id = checkpoint.pipeline_run_id
        checkpoint_mgr = create_checkpoint_manager(
            self.output_dir,
            self.target_name,
            run_id=run_id,
            storage_config=self.storage_config,
        )
        completed = {
            str(stage).strip()
            for stage in (getattr(checkpoint, "completed_stages", []) or [])
            if str(stage).strip()
        }
        payload = self._load_context_payload(checkpoint_mgr, completed)
        if payload is None:
            logger.warning(
                "Recovery Manager: checkpoint %s has no usable context snapshot; starting fresh",
                run_id,
            )
            return self._fresh(mode)

        if not self._payload_is_compatible(payload, run_id):
            return self._fresh(mode)

        wal = self._open_wal(run_id)
        wal_state = self._replay_journal(wal, mode)
        checkpoint_counts = self._counts_from_payload(payload)
        wal_counts = self._counts_from_wal(wal_state)
        source = "checkpoint+wal" if wal_state is not None else "checkpoint"
        remaining = [stage for stage in self.stage_order if stage not in completed]
        verify_report = self._build_verify_report(checkpoint_counts, wal_counts, source, run_id)
        if mode is WalReplayMode.VERIFY:
            logger.info("Recovery Manager verify: %s", verify_report)

        return ReconstructedState(
            run_id=run_id,
            can_recover=True,
            source=source,
            mode=mode,
            checkpoint=checkpoint,
            checkpoint_mgr=checkpoint_mgr,
            context_payload=payload,
            completed_stages=completed,
            remaining_stages=remaining,
            wal=wal,
            wal_state=wal_state,
            checkpoint_counts=checkpoint_counts,
            wal_counts=wal_counts,
            verify_report=verify_report,
            execute_stages=mode is not WalReplayMode.DRY_RUN,
        )

    def _fresh(self, mode: WalReplayMode) -> ReconstructedState:
        run_id = generate_run_id()
        wal = self._open_wal(run_id)
        checkpoint_mgr = create_checkpoint_manager(
            self.output_dir,
            self.target_name,
            run_id=run_id,
            storage_config=self.storage_config,
        )
        return ReconstructedState(
            run_id=run_id,
            can_recover=False,
            source="none",
            mode=mode,
            checkpoint_mgr=checkpoint_mgr,
            remaining_stages=list(self.stage_order),
            wal=wal,
            execute_stages=mode is not WalReplayMode.DRY_RUN,
        )

    def _load_checkpoint_snapshot(self, resume_from: str | None) -> CheckpointState | None:
        if resume_from:
            targeted = self._load_specific_run(resume_from)
            if targeted is not None:
                return targeted
            logger.warning(
                "Recovery Manager: --resume-from=%s not found; falling back to best checkpoint",
                resume_from,
            )
        can_recover, state = attempt_recovery(
            self.output_dir,
            self.target_name,
            force_fresh=False,
            storage_config=self.storage_config,
        )
        if can_recover and state is not None:
            return state
        return None

    def _load_specific_run(self, run_id: str) -> CheckpointState | None:
        from src.core.storage.factory import create_checkpoint_store

        checkpoint_dir = self.output_dir / self.target_name / "checkpoints"
        store = create_checkpoint_store(self.storage_config, checkpoint_dir)
        payload = store.read_latest(run_id)
        if not payload:
            return None
        try:
            return CheckpointState.from_dict(payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Recovery Manager: failed to load run %s: %s", run_id, exc)
            return None

    def _load_context_payload(
        self, checkpoint_mgr: Any, completed: set[str]
    ) -> dict[str, Any] | None:
        if hasattr(checkpoint_mgr, "load_latest_context_snapshot"):
            payload = checkpoint_mgr.load_latest_context_snapshot(completed)
        else:
            payload = None
        if isinstance(payload, dict) and {"scope_entries", "stage_status"}.issubset(payload):
            return payload
        return None

    def _payload_is_compatible(self, payload: dict[str, Any], run_id: str) -> bool:
        payload_target = str(payload.get("target_name", "")).strip()
        try:
            payload_version = int(payload.get("checkpoint_version", 0) or 0)
        except (TypeError, ValueError):
            payload_version = 0
        if payload_target and payload_target != self.target_name:
            logger.warning(
                "Recovery Manager: skipping run=%s target mismatch (%r != %r)",
                run_id,
                payload_target,
                self.target_name,
            )
            return False
        if payload_version < self.min_checkpoint_version:
            logger.warning(
                "Recovery Manager: skipping run=%s checkpoint_version %s < min %s",
                run_id,
                payload_version,
                self.min_checkpoint_version,
            )
            return False
        return True

    def _open_wal(self, run_id: str) -> Any:
        factory = self._wal_factory
        if factory is None:
            from src.infrastructure.frontier.wal import FrontierWAL

            factory = FrontierWAL
        wal_aof_dir = self.output_dir / ".wal"
        return factory(self.redis_url, run_id, aof_dir=wal_aof_dir)

    def _replay_journal(self, wal: Any, mode: WalReplayMode) -> Any | None:
        if wal is None or not hasattr(wal, "recover_state"):
            return None
        if mode is WalReplayMode.DRY_RUN:
            # Still reconstruct so remaining-stage planning is truthful.
            pass
        try:
            return wal.recover_state()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Recovery Manager: WAL recover_state failed: %s", exc)
            return None

    @staticmethod
    def _coerce_mode(value: str | WalReplayMode) -> WalReplayMode:
        if isinstance(value, WalReplayMode):
            return value
        normalized = str(value or "replay").strip().lower().replace("_", "-")
        for mode in WalReplayMode:
            if mode.value == normalized:
                return mode
        logger.warning("Recovery Manager: unknown wal-replay mode %r; using replay", value)
        return WalReplayMode.REPLAY

    @staticmethod
    def _counts_from_payload(payload: dict[str, Any]) -> dict[str, int]:
        neural = payload.get("_neural_state") or payload.get("neural_state") or {}
        if not isinstance(neural, dict):
            neural = {}
        return {
            "subdomains": _len_of(neural.get("subdomains") or payload.get("subdomains")),
            "urls": _len_of(neural.get("urls") or payload.get("urls")),
            "findings": _len_of(neural.get("findings") or payload.get("reportable_findings")),
        }

    @staticmethod
    def _counts_from_wal(wal_state: Any) -> dict[str, int]:
        if wal_state is None:
            return {"subdomains": 0, "urls": 0, "findings": 0}
        try:
            return {
                "subdomains": len(wal_state.subdomains.to_set()),
                "urls": len(wal_state.urls.to_set()),
                "findings": len(wal_state.findings),
            }
        except Exception:  # noqa: BLE001
            return {"subdomains": 0, "urls": 0, "findings": 0}

    @staticmethod
    def _build_verify_report(
        checkpoint_counts: dict[str, int],
        wal_counts: dict[str, int],
        source: str,
        run_id: str,
    ) -> dict[str, Any]:
        deltas = {
            key: wal_counts.get(key, 0) - checkpoint_counts.get(key, 0)
            for key in ("subdomains", "urls", "findings")
        }
        return {
            "run_id": run_id,
            "source": source,
            "checkpoint": checkpoint_counts,
            "wal": wal_counts,
            "journal_ahead": deltas,
        }


def _len_of(value: Any) -> int:
    if value is None:
        return 0
    try:
        return len(value)
    except TypeError:
        return 0
