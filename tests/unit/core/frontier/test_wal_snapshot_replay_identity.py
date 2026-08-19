"""Prove snapshot + WAL recovery equals pre-crash state.

Acceptance: recovered state == pre-crash state. Not merely "recovery
completed". These tests specifically guard R0-2 (double-apply of
already-snapshotted entries) and the 0bd3027a unfiltered journal pass
that ``list.extend``'d ``merged_findings`` / ``live_hosts``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.core.frontier.state import NeuralState
from src.core.models.stage_result import PipelineContext, StageResult
from src.infrastructure.frontier.wal import FrontierWAL


def _make_wal(tmp_path: Path, run_id: str) -> FrontierWAL:
    return FrontierWAL(None, run_id, aof_dir=str(tmp_path / ".wal"))


def _finding_ids(state: NeuralState) -> set[str]:
    ids: set[str] = set()
    for item in state.findings.values():
        if isinstance(item, dict):
            ids.add(str(item.get("id") or item.get("title") or item))
        else:
            ids.add(str(item))
    return ids


def _assert_crdt_equal(left: NeuralState, right: NeuralState) -> None:
    assert left.subdomains.to_set() == right.subdomains.to_set()
    assert left.urls.to_set() == right.urls.to_set()
    assert _finding_ids(left) == _finding_ids(right)
    assert left.last_wal_id == right.last_wal_id
    assert left.applied_wal_ids == right.applied_wal_ids
    assert left.subdomains.tombstone_count == right.subdomains.tombstone_count
    assert left.urls.tombstone_count == right.urls.tombstone_count
    assert left.findings.tombstone_count == right.findings.tombstone_count


def _apply_and_log(
    wal: FrontierWAL,
    live: NeuralState,
    ctx: PipelineContext,
    stage: str,
    delta: dict[str, Any],
) -> str:
    wal_id = wal.log_delta(stage, delta)
    assert wal_id is not None
    payload = dict(delta)
    payload["_wal_id"] = wal_id
    live.apply_delta(payload)
    ctx.result.apply_state_delta(payload)
    return wal_id


def _journal_replay(wal: FrontierWAL, ctx: PipelineContext, start_id: str | None) -> None:
    exclude = set(ctx.result._journal_applied_ids)
    for entry in wal.recover_deltas(start_id, exclude_ids=exclude):
        delta = entry.get("delta")
        if isinstance(delta, dict):
            delta.setdefault("_wal_id", entry.get("id"))
            ctx.result.apply_journal_fields(delta)


def test_snapshot_n_deltas_compact_crash_recover_identity(tmp_path: Path) -> None:
    """snapshot → N deltas → compact → crash → recover → exact equality."""
    run_id = "identity-compact-crash"
    wal = _make_wal(tmp_path, run_id)
    live = NeuralState()
    ctx = PipelineContext(result=StageResult())

    _apply_and_log(
        wal,
        live,
        ctx,
        "recon",
        {
            "subdomains": ["a.example.com"],
            "urls": ["https://a.example.com/"],
            "findings": [{"id": "f1", "title": "F1", "severity": "low"}],
            "live_hosts": ["https://a.example.com"],
            "merged_findings": [{"id": "m1", "title": "M1"}],
            "module_metrics": {"recon": {"hosts": 1}},
        },
    )
    assert wal.persist_snapshot(live, reason="checkpoint") is True

    for index in range(5):
        _apply_and_log(
            wal,
            live,
            ctx,
            "scan",
            {
                "subdomains": [f"s{index}.example.com"],
                "urls": [f"https://s{index}.example.com/p"],
                "findings": [
                    {"id": f"f{index + 2}", "title": f"F{index + 2}", "severity": "medium"}
                ],
                "live_hosts": [f"https://s{index}.example.com"],
                "merged_findings": [{"id": f"m{index + 2}", "title": f"M{index + 2}"}],
                "waf_findings": [{"id": f"w{index}", "title": f"W{index}"}],
            },
        )

    pre_subdomains = set(live.subdomains.to_set())
    pre_urls = set(live.urls.to_set())
    pre_findings = _finding_ids(live)
    pre_last = live.last_wal_id
    pre_applied = set(live.applied_wal_ids)

    assert wal.compact_after_snapshot(live, keep_entries=100) is True

    # Crash: drop the live instance, open a fresh WAL on the same files.
    # Compact rewrote the AOF to the exclusive tail (empty here) and
    # persisted the full CRDT snapshot. recover_state must equal live.
    del wal
    crashed = _make_wal(tmp_path, run_id)
    recovered = crashed.recover_state()

    assert recovered.subdomains.to_set() == pre_subdomains
    assert recovered.urls.to_set() == pre_urls
    assert _finding_ids(recovered) == pre_findings
    assert recovered.last_wal_id == pre_last
    assert recovered.applied_wal_ids == pre_applied
    _assert_crdt_equal(recovered, live)
    # Post-compact journal must not re-introduce snapshotted rows.
    assert (
        crashed.recover_deltas(recovered.last_wal_id, exclude_ids=recovered.applied_wal_ids) == []
    )

    crashed.cleanup()


def test_snapshot_then_tail_replay_does_not_double_apply(tmp_path: Path) -> None:
    """Snapshot mid-run, keep the tail, crash, recover without doubling lists."""
    run_id = "identity-tail-replay"
    wal = _make_wal(tmp_path, run_id)
    live = NeuralState()
    ctx = PipelineContext(result=StageResult())

    _apply_and_log(
        wal,
        live,
        ctx,
        "recon",
        {
            "subdomains": ["edge.example.com"],
            "live_hosts": ["https://edge.example.com"],
            "merged_findings": [{"id": "m-edge", "title": "edge"}],
            "findings": [{"id": "f-edge", "title": "edge"}],
        },
    )
    snapshot_cursor = live.last_wal_id
    snapshot_applied = set(live.applied_wal_ids)
    assert wal.persist_snapshot(live, reason="checkpoint") is True
    assert wal.compact_after_snapshot(live, keep_entries=10) is True

    checkpoint_ctx = PipelineContext(result=StageResult.from_dict(ctx.result.to_dict()))
    checkpoint_hosts = set(checkpoint_ctx.result.live_hosts)
    checkpoint_merged = list(checkpoint_ctx.result.merged_findings)

    for index in range(3):
        _apply_and_log(
            wal,
            live,
            ctx,
            "scan",
            {
                "subdomains": [f"tail{index}.example.com"],
                "live_hosts": [f"https://tail{index}.example.com"],
                "merged_findings": [{"id": f"m-tail{index}", "title": f"tail{index}"}],
                "findings": [{"id": f"f-tail{index}", "title": f"tail{index}"}],
            },
        )

    pre_hosts = set(ctx.result.live_hosts)
    pre_merged = list(ctx.result.merged_findings)

    del wal
    crashed = _make_wal(tmp_path, run_id)
    recovered = crashed.recover_state()
    _assert_crdt_equal(recovered, live)

    # Simulate run_secured: restore checkpoint, then journal-field pass
    # keyed off the *pre-merge* checkpoint cursor.
    restored = checkpoint_ctx
    journal_cursor = restored.result._neural_state.last_wal_id
    journal_exclude = set(restored.result._neural_state.applied_wal_ids)
    restored.result._journal_applied_ids.update(journal_exclude)
    restored.result._neural_state.merge(recovered)
    _journal_replay(crashed, restored, start_id=journal_cursor)

    assert journal_cursor == snapshot_cursor
    assert journal_exclude == snapshot_applied
    assert set(restored.result.live_hosts) == pre_hosts
    assert restored.result.merged_findings == pre_merged
    assert restored.result.merged_findings.count({"id": "m-edge", "title": "edge"}) == 1
    assert set(checkpoint_hosts).issubset(pre_hosts)
    assert checkpoint_merged == [{"id": "m-edge", "title": "edge"}]

    # A second journal pass must be a no-op (idempotent).
    _journal_replay(crashed, restored, start_id=journal_cursor)
    assert restored.result.merged_findings == pre_merged
    assert set(restored.result.live_hosts) == pre_hosts

    crashed.cleanup()


def test_missing_aof_cursor_does_not_replay_full_journal(tmp_path: Path) -> None:
    """R0-2: a missing non-Redis start_id must not return every AOF entry."""
    run_id = "r0-2-missing-cursor"
    wal = _make_wal(tmp_path, run_id)
    for host in ("one.example.com", "two.example.com", "three.example.com"):
        assert wal.log_delta("recon", {"subdomains": [host]}) is not None

    # Future / unknown AOF cursor: refuse full replay.
    replayed = wal.recover_deltas("aof-9999999999.000000000-deadbeef")
    assert replayed == []

    # Garbage non-stream cursor: also refuse full replay.
    assert wal.recover_deltas("not-a-real-cursor") == []

    wal.cleanup()


def test_recover_state_skips_snapshotted_entries(tmp_path: Path) -> None:
    """Full AOF still present: recover_state must not re-apply snapshot rows."""
    run_id = "no-double-crdt"
    wal = _make_wal(tmp_path, run_id)
    live = NeuralState()
    ctx = PipelineContext(result=StageResult())

    _apply_and_log(
        wal,
        live,
        ctx,
        "recon",
        {
            "subdomains": ["kept.example.com"],
            "findings": [{"id": "f-kept", "title": "kept"}],
        },
    )
    assert wal.persist_snapshot(live, reason="checkpoint") is True
    _apply_and_log(
        wal,
        live,
        ctx,
        "scan",
        {
            "subdomains": ["after.example.com"],
            "findings": [{"id": "f-after", "title": "after"}],
        },
    )

    crashed = _make_wal(tmp_path, run_id)
    recovered = crashed.recover_state()
    _assert_crdt_equal(recovered, live)
    assert recovered.subdomains.to_set() == {"kept.example.com", "after.example.com"}
    assert _finding_ids(recovered) == {"f-kept", "f-after"}

    # Snapshot cursor + exclude_ids must drop the snapshotted row.
    cursor, applied = crashed.snapshot_replay_cursor()
    tail = crashed.recover_deltas(cursor, exclude_ids=applied)
    assert len(tail) == 1
    assert tail[0]["delta"]["subdomains"] == ["after.example.com"]

    crashed.cleanup()
    wal.cleanup()


def test_aof_snapshot_survives_inactive_redis(tmp_path: Path) -> None:
    wal = FrontierWAL(None, "aof-snap-only", aof_dir=str(tmp_path))
    state = NeuralState()
    state.apply_delta(
        {
            "_wal_id": "aof-111.0-abc",
            "subdomains": ["snap-only.example.com"],
            "findings": [{"id": "f-snap", "title": "snap"}],
        }
    )
    assert wal.persist_snapshot(state, reason="checkpoint") is True
    assert wal._snapshot_path().exists()

    reopened = FrontierWAL(None, "aof-snap-only", aof_dir=str(tmp_path))
    envelope = reopened.load_snapshot()
    assert envelope is not None
    assert envelope["snapshot"]["last_wal_id"] == "aof-111.0-abc"
    recovered = reopened.recover_state()
    assert "snap-only.example.com" in recovered.subdomains.to_set()
    assert _finding_ids(recovered) == {"f-snap"}
    reopened.cleanup()
