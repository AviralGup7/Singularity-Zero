"""Architecture review Phase-5 remaining-item tests."""

from __future__ import annotations

import json
from pathlib import Path


def test_partition_wal_local_replicate_and_caught_up():
    """Use duck-typed WALs so the test does not need redis (PartitionWAL import chain)."""
    from types import SimpleNamespace

    from src.infrastructure.frontier.replication import (
        PartitionWALReplicator,
        set_partition_wal_replicator,
    )

    class _FakeWAL:
        def __init__(self) -> None:
            self.records: list[tuple[object, bool]] = []

        def load_all_entries(self):
            return list(self.records)

        def append_entry(self, entry, committed: bool = False, sync: bool = True, **kwargs):
            self.records.append((entry, committed))

    src = _FakeWAL()
    sink = _FakeWAL()
    e1 = SimpleNamespace(raft_index=1, raft_term=1)
    e2 = SimpleNamespace(raft_index=2, raft_term=1)
    src.records.append((e1, True))
    src.records.append((e2, True))
    src.records.append((SimpleNamespace(raft_index=3, raft_term=1), False))  # uncommitted skip

    rep = PartitionWALReplicator(source_wal=src, sink_wal=sink, enabled=True)
    n = rep.replicate_range(from_index=0)
    assert n == 2
    assert rep.caught_up(target_index=2) is True
    assert rep.caught_up(target_index=9) is False
    # idempotent re-copy
    assert rep.replicate_range(from_index=0) == 0
    set_partition_wal_replicator(rep)
    try:
        assert rep.status()["enabled"] is True
        assert rep.status()["authority"] is True
    finally:
        set_partition_wal_replicator(None)


def test_authorizer_wal_consume_fn_hook():
    from src.decision.authorization import ExecutionAuthorizer
    from src.decision.hunt_budget import HuntBudget, HuntBudgetEnforcer

    calls: list[str] = []

    def wal_fn(tid: str) -> bool:
        calls.append(tid)
        return True

    auth = ExecutionAuthorizer(
        budget_enforcer=HuntBudgetEnforcer(HuntBudget(max_requests=10), label="t"),
        wal_consume_fn=wal_fn,
        require_wal_consume=True,
    )
    # remember path doesn't call wal; set_wal and consume need a real ticket
    auth.set_wal_consume_fn(wal_fn, require=False)
    assert auth._wal_consume_fn is wal_fn


def test_raft_capability_report_script(tmp_path, monkeypatch):
    import subprocess
    import sys

    out = subprocess.check_output(
        [sys.executable, "scripts/generate_raft_capability_report.py"],
        cwd=str(Path.cwd()),
        text=True,
    )
    report = json.loads(out)
    assert report["default_mode"] == "single_node_quorum_1"
    assert "test_files" in report
    assert report["test_files"].get("test_raft_cluster") is True


def test_kernel_lab_profile_disables_require(monkeypatch):
    from src.sandbox.process_sandbox import ProcessSandbox

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("CSTP_LAB_PROFILE", "true")
    monkeypatch.delenv("REQUIRE_KERNEL_SANDBOX", raising=False)
    monkeypatch.delenv("REQUIRE_NETNS", raising=False)
    assert ProcessSandbox._env_requires_kernel_sandbox() is False
    monkeypatch.delenv("CSTP_LAB_PROFILE", raising=False)
    monkeypatch.setenv("REQUIRE_NETNS", "true")
    assert ProcessSandbox._env_requires_kernel_sandbox() is True


def test_snapshot_manifest_recovery_helper_import():
    from src.core.recovery.manager import RecoveryManager

    assert hasattr(RecoveryManager, "_assert_checkpoint_manifest_safe")
