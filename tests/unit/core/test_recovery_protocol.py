"""I35 formal recovery protocol: every durable boundary and crash window."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from src.core.checkpoint.base import CheckpointState
from src.core.checkpoint.migrations import GLOBAL_MIGRATION_REGISTRY
from src.core.contracts.command_envelope import EventEnvelope
from src.core.frontier.event_delivery import (
    DeliveryLedger,
    reconcile_delivery_against_outbox,
)
from src.core.frontier.outbox import DurableOutboxLedger
from src.core.frontier.recovery_protocol import (
    CRASH_RESOLUTIONS,
    DURABLE_BOUNDARIES,
    I35_RECOVERY_PROTOCOL,
    CrashWindow,
    DurableObject,
    ObservedDurableState,
    RecoveryAction,
    RecoveryPhase,
    RecoveryPlane,
    RecoveryProtocolError,
    RecoverySession,
    UnsupportedSchemaError,
    assert_schema_readable,
    crash_catalog,
    durable_catalog,
    rebuild_outbox_from_committed_entries,
    resolution_for,
    resolve_compensation_crash,
    run_recovery_protocol,
)


def test_i35_catalogs_cover_every_object_and_window() -> None:
    assert set(DURABLE_BOUNDARIES) == set(DurableObject)
    assert set(CRASH_RESOLUTIONS) == set(CrashWindow)
    assert len(durable_catalog()) == len(DurableObject)
    assert len(crash_catalog()) == len(CrashWindow)
    for boundary in DURABLE_BOUNDARIES.values():
        assert boundary.authoritative_source
        assert boundary.reconstructed_from
        assert boundary.schema_newer_than_reader
    for window in CrashWindow:
        res = resolution_for(window)
        assert res.partition_action in RecoveryAction
        assert res.frontier_action in RecoveryAction


def test_i35_schema_newer_than_reader_is_unreadable() -> None:
    assert_schema_readable(2, reader_version=2)
    with pytest.raises(UnsupportedSchemaError, match="I35"):
        assert_schema_readable(3, reader_version=2)
    with pytest.raises(UnsupportedSchemaError, match="I35"):
        GLOBAL_MIGRATION_REGISTRY.migrate({"schema_version": 99, "pipeline_run_id": "r"})
    with pytest.raises(UnsupportedSchemaError, match="I35"):
        CheckpointState.from_dict({"pipeline_run_id": "r", "schema_version": 99})


def test_i35_older_schema_still_migrates() -> None:
    migrated = GLOBAL_MIGRATION_REGISTRY.migrate({"schema_version": 1, "pipeline_run_id": "r"})
    assert migrated["schema_version"] == 2


def test_i35_partition_snapshot_ahead_of_wal_fail_closed() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.PARTITION,
            snapshot_present=True,
            wal_present=True,
            snapshot_schema_version=2,
            snapshot_log_index=40,
            wal_commit_index=10,
        )
    )
    assert verdict.phase is RecoveryPhase.FAIL_CLOSED
    assert CrashWindow.SNAPSHOT_AHEAD_OF_WAL in verdict.windows
    assert verdict.discard_snapshot is True


def test_i35_frontier_truncated_wal_keeps_stale_snapshot() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.FRONTIER,
            snapshot_present=True,
            wal_present=True,
            snapshot_schema_version=2,
            snapshot_log_index=5,
            wal_commit_index=5,
            wal_truncated_after_snapshot=True,
        )
    )
    assert verdict.phase is RecoveryPhase.READY
    assert verdict.snapshot_stale is True
    assert verdict.action is RecoveryAction.STALE_CONTINUE
    assert CrashWindow.WAL_TRUNCATED_AFTER_SNAPSHOT in verdict.windows


def test_i35_partition_truncated_wal_fail_closed() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.PARTITION,
            snapshot_present=True,
            wal_present=True,
            snapshot_schema_version=2,
            wal_truncated_after_snapshot=True,
        )
    )
    assert verdict.phase is RecoveryPhase.FAIL_CLOSED


def test_i35_schema_newer_frontier_starts_fresh() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.FRONTIER,
            snapshot_present=True,
            wal_present=True,
            snapshot_schema_version=9,
            reader_schema_version=2,
        )
    )
    assert verdict.phase is RecoveryPhase.FRESH
    assert CrashWindow.SCHEMA_NEWER_THAN_READER in verdict.windows


def test_i35_healthy_behind_snapshot_replays() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.FRONTIER,
            snapshot_present=True,
            wal_present=True,
            snapshot_schema_version=2,
            snapshot_log_index=3,
            wal_commit_index=10,
            snapshot_last_wal_id="wal_3",
            wal_ids=frozenset({"wal_3", "wal_4", "wal_10"}),
        )
    )
    assert verdict.phase is RecoveryPhase.READY
    assert CrashWindow.SNAPSHOT_BEHIND_WAL in verdict.windows
    assert verdict.discard_snapshot is False


def test_i35_fsm_without_outbox_rebuilds() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.PARTITION,
            wal_present=True,
            snapshot_present=False,
            fsm_applied_index=4,
            fsm_event_ids=frozenset({"evt_a", "evt_b"}),
            outbox_event_ids=frozenset({"evt_a"}),
        )
    )
    assert verdict.phase is RecoveryPhase.READY
    assert verdict.rebuild_outbox is True
    assert CrashWindow.FSM_WITHOUT_OUTBOX in verdict.windows


def test_i35_outbox_without_fsm_ignores_orphans() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.PARTITION,
            wal_present=False,
            snapshot_present=False,
            fsm_applied_index=0,
            fsm_event_ids=frozenset(),
            outbox_event_ids=frozenset({"evt_orphan"}),
        )
    )
    # no snapshot and no wal → FRESH before outbox reconcile
    assert verdict.phase is RecoveryPhase.FRESH

    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.PARTITION,
            wal_present=True,
            snapshot_present=False,
            fsm_applied_index=0,
            fsm_event_ids=frozenset(),
            outbox_event_ids=frozenset({"evt_orphan"}),
        )
    )
    assert verdict.phase is RecoveryPhase.READY
    assert CrashWindow.OUTBOX_WITHOUT_FSM in verdict.windows
    assert verdict.orphan_outbox_ids == ("evt_orphan",)


def test_i35_delivery_ahead_of_outbox_is_discarded() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.FRONTIER,
            wal_present=True,
            snapshot_present=False,
            outbox_event_ids=frozenset({"evt_1"}),
            delivered_event_ids=frozenset({"evt_1", "evt_ghost"}),
        )
    )
    assert CrashWindow.DELIVERY_AHEAD_OF_OUTBOX in verdict.windows
    assert "evt_ghost" in verdict.discarded_delivery_ids
    assert verdict.replay_delivery is True


def test_i35_outbox_appended_delivery_missing_replays() -> None:
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.FRONTIER,
            wal_present=True,
            snapshot_present=False,
            outbox_event_ids=frozenset({"evt_1", "evt_2"}),
            delivered_event_ids=frozenset({"evt_1"}),
        )
    )
    assert CrashWindow.OUTBOX_APPENDED_DELIVERY_MISSING in verdict.windows
    assert verdict.replay_delivery is True
    assert verdict.phase is RecoveryPhase.READY


def test_i35_compensation_crash_is_idempotent() -> None:
    assert resolve_compensation_crash("compensated") is RecoveryAction.IDEMPOTENT_NOOP
    assert resolve_compensation_crash("consumed") is RecoveryAction.IDEMPOTENT_NOOP
    assert resolve_compensation_crash("reserved") is RecoveryAction.IDEMPOTENT_REPLAY
    assert resolve_compensation_crash("active") is RecoveryAction.FAIL_CLOSED
    verdict = run_recovery_protocol(
        ObservedDurableState(
            plane=RecoveryPlane.PARTITION,
            wal_present=True,
            snapshot_present=False,
            compensation_in_progress=True,
            compensation_lease_status="reserved",
        )
    )
    assert CrashWindow.CRASH_DURING_COMPENSATION in verdict.windows
    assert verdict.phase is RecoveryPhase.READY


def test_i35_illegal_phase_transition_fail_closed() -> None:
    session = RecoverySession()
    with pytest.raises(RecoveryProtocolError, match=I35_RECOVERY_PROTOCOL):
        session.advance(RecoveryPhase.READY)


def test_i35_rebuild_outbox_from_committed_is_idempotent() -> None:
    @dataclass
    class _Entry:
        emitted_events: tuple[EventEnvelope, ...]

    event = EventEnvelope(
        event_id="evt_rebuild_1",
        event_type="FINDING_CREATED",
        aggregate_id="exec",
        aggregate_version=1,
        payload={"k": 1},
        correlation_id="c",
        causation_id="w",
    )
    outbox = DurableOutboxLedger(partition_id="P-0000", outbox_dir=None)
    entries = [_Entry(emitted_events=(event,))]
    assert rebuild_outbox_from_committed_entries(entries, outbox) == 1
    assert rebuild_outbox_from_committed_entries(entries, outbox) == 0
    assert outbox.event_count == 1


def test_i35_delivery_ledger_drops_ids_not_in_outbox() -> None:
    ledger = DeliveryLedger()
    ledger.record("dlv_keep")
    ledger.record("dlv_ghost")
    # reconcile expects EventIds and derives DeliveryIds; seed via discard_unknown
    removed = ledger.discard_unknown(["dlv_keep"])
    assert removed == 1
    assert "dlv_ghost" not in ledger.delivered_ids()
    assert "dlv_keep" in ledger.delivered_ids()


def test_i35_reconcile_delivery_uses_derived_delivery_ids() -> None:
    from src.core.frontier.causal_identity import derive_delivery_id

    ledger = DeliveryLedger()
    keep = derive_delivery_id("evt_keep", 1)
    ghost = derive_delivery_id("evt_ghost", 1)
    ledger.record(keep)
    ledger.record(ghost)
    removed = reconcile_delivery_against_outbox(ledger, ["evt_keep"])
    assert removed == 1
    assert keep in ledger.delivered_ids()
    assert ghost not in ledger.delivered_ids()


def test_i35_checkpoint_snapshot_is_not_authority() -> None:
    boundary = DURABLE_BOUNDARIES[DurableObject.CHECKPOINT_SNAPSHOT]
    assert "none" in boundary.authoritative_source.lower()
    assert boundary.reconstructible is True
    wal = DURABLE_BOUNDARIES[DurableObject.PARTITION_WAL]
    assert wal.reconstructible is False
    delivery = DURABLE_BOUNDARIES[DurableObject.DELIVERY_LEDGER]
    assert delivery.reconstructible is True
    assert "empty" in delivery.reconstructed_from.lower()
