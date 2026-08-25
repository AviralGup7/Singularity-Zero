"""Unit tests for the snapshot + journal Recovery Manager."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from src.core.checkpoint.base import CheckpointState
from src.core.recovery.manager import RecoveryManager, WalReplayMode


@dataclass
class _FakeWalState:
    subdomains: Any
    urls: Any
    findings: dict[str, Any] = field(default_factory=dict)


@dataclass
class _FakeSet:
    values: set[str]

    def to_set(self) -> set[str]:
        return set(self.values)


class _FakeWal:
    def __init__(self, redis_url: str | None, run_id: str, aof_dir: Path | None = None) -> None:
        self.redis_url = redis_url
        self.run_id = run_id
        self.aof_dir = aof_dir
        self.recovered: _FakeWalState | None = None

    def recover_state(self) -> _FakeWalState:
        return self.recovered or _FakeWalState(
            subdomains=_FakeSet({"a.example.com", "b.example.com"}),
            urls=_FakeSet({"https://a.example.com/"}),
            findings={"f1": {"id": "f1"}},
        )


class _FakeCheckpointMgr:
    def __init__(self, payload: dict[str, Any] | None) -> None:
        self.payload = payload

    def load_latest_context_snapshot(self, _completed: set[str]) -> dict[str, Any] | None:
        return self.payload


@pytest.mark.unit
def test_force_fresh_skips_snapshot(tmp_path: Path) -> None:
    manager = RecoveryManager(
        tmp_path,
        "example",
        stage_order=["recon", "scan"],
        wal_factory=_FakeWal,
    )
    state = manager.recover(force_fresh=True)
    assert state.can_recover is False
    assert state.source == "none"
    assert state.remaining_stages == ["recon", "scan"]
    assert isinstance(state.wal, _FakeWal)


@pytest.mark.unit
def test_unknown_wal_mode_falls_back_to_replay() -> None:
    assert RecoveryManager._coerce_mode("nope") is WalReplayMode.REPLAY
    assert RecoveryManager._coerce_mode("dry_run") is WalReplayMode.DRY_RUN


@pytest.mark.unit
def test_reconstruct_merges_wal_journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checkpoint = CheckpointState(
        pipeline_run_id="run-abc",
        completed_stages=["recon"],
        checkpoint_version=2,
    )
    payload = {
        "scope_entries": ["example.com"],
        "stage_status": {"recon": "completed"},
        "target_name": "example",
        "checkpoint_version": 2,
        "subdomains": ["a.example.com"],
        "urls": [],
        "reportable_findings": [],
    }

    monkeypatch.setattr(
        "src.core.recovery.manager.attempt_recovery",
        lambda *a, **k: (True, checkpoint),
    )
    monkeypatch.setattr(
        "src.core.recovery.manager.create_checkpoint_manager",
        lambda *a, **k: _FakeCheckpointMgr(payload),
    )

    manager = RecoveryManager(
        tmp_path,
        "example",
        stage_order=["recon", "scan", "report"],
        wal_factory=_FakeWal,
    )
    state = manager.recover()
    assert state.can_recover is True
    assert state.source == "checkpoint+wal"
    assert state.completed_stages == {"recon"}
    assert state.remaining_stages == ["scan", "report"]
    assert state.wal_counts["subdomains"] == 2
    assert state.wal_counts["urls"] == 1
    assert state.wal_counts["findings"] == 1
    assert state.execute_stages is True


@pytest.mark.unit
def test_dry_run_does_not_execute_stages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checkpoint = CheckpointState(
        pipeline_run_id="run-dry",
        completed_stages=["recon"],
        checkpoint_version=2,
    )
    payload = {
        "scope_entries": ["example.com"],
        "stage_status": {"recon": "completed"},
        "target_name": "example",
        "checkpoint_version": 2,
    }
    monkeypatch.setattr(
        "src.core.recovery.manager.attempt_recovery",
        lambda *a, **k: (True, checkpoint),
    )
    monkeypatch.setattr(
        "src.core.recovery.manager.create_checkpoint_manager",
        lambda *a, **k: _FakeCheckpointMgr(payload),
    )
    manager = RecoveryManager(
        tmp_path,
        "example",
        stage_order=["recon", "scan"],
        wal_factory=_FakeWal,
    )
    state = manager.recover(wal_replay="dry-run")
    assert state.mode is WalReplayMode.DRY_RUN
    assert state.execute_stages is False
    assert state.verify_report["run_id"] == "run-dry"


@pytest.mark.unit
def test_verify_report_shows_journal_ahead(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    checkpoint = CheckpointState(
        pipeline_run_id="run-v",
        completed_stages=["recon"],
        checkpoint_version=2,
    )
    payload = {
        "scope_entries": ["example.com"],
        "stage_status": {"recon": "completed"},
        "target_name": "example",
        "checkpoint_version": 2,
        "subdomains": ["a.example.com"],
        "urls": [],
        "reportable_findings": [],
    }
    monkeypatch.setattr(
        "src.core.recovery.manager.attempt_recovery",
        lambda *a, **k: (True, checkpoint),
    )
    monkeypatch.setattr(
        "src.core.recovery.manager.create_checkpoint_manager",
        lambda *a, **k: _FakeCheckpointMgr(payload),
    )
    manager = RecoveryManager(
        tmp_path,
        "example",
        stage_order=["recon"],
        wal_factory=_FakeWal,
    )
    state = manager.recover(wal_replay="verify")
    assert state.mode is WalReplayMode.VERIFY
    assert state.verify_report["journal_ahead"]["subdomains"] == 1
    assert state.verify_report["journal_ahead"]["urls"] == 1
    assert state.execute_stages is True
    assert state.recovery_phase == "ready"


@pytest.mark.unit
def test_i35_newer_checkpoint_schema_starts_fresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkpoint = CheckpointState(
        pipeline_run_id="run-future",
        completed_stages=["recon"],
        checkpoint_version=2,
    )
    payload = {
        "scope_entries": ["example.com"],
        "stage_status": {"recon": "completed"},
        "target_name": "example",
        "checkpoint_version": 2,
        "schema_version": 99,
    }
    monkeypatch.setattr(
        "src.core.recovery.manager.attempt_recovery",
        lambda *a, **k: (True, checkpoint),
    )
    monkeypatch.setattr(
        "src.core.recovery.manager.create_checkpoint_manager",
        lambda *a, **k: _FakeCheckpointMgr(payload),
    )
    manager = RecoveryManager(
        tmp_path,
        "example",
        stage_order=["recon", "scan"],
        wal_factory=_FakeWal,
    )
    state = manager.recover()
    assert state.can_recover is False
    assert state.source == "none"
    assert state.recovery_phase == "fresh"
