"""I35 — formal recovery protocol for every durable boundary.

I34 names what a *failure class* may do. This module names what happens
at every *persistent object* when the process restarts or two stores
disagree. Exotic multi-node repair is still out of scope; the protocol
still has to answer the crash questions.

Recovery is a state machine, not a table lookup:

    UNINITIALIZED → LOAD_SNAPSHOT → VERIFY_SNAPSHOT → LOAD_WAL
      → RECONCILE_SNAPSHOT_WAL → REPLAY_WAL → RECONSTRUCT_FSM
      → RECONCILE_OUTBOX → RECONCILE_DELIVERY → VERIFY_INVARIANTS
      → READY | FAIL_CLOSED | FRESH
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

I35_RECOVERY_PROTOCOL = "I35"

READER_SCHEMA_VERSION = 2


class DurableObject(StrEnum):
    PARTITION_WAL = "partition_wal"
    PARTITION_FSM = "partition_fsm"
    FRONTIER_WAL = "frontier_wal"
    CHECKPOINT_SNAPSHOT = "checkpoint_snapshot"
    DURABLE_OUTBOX = "durable_outbox"
    DELIVERY_LEDGER = "delivery_ledger"
    GLOBAL_BUDGET = "global_budget"
    SETTLEMENT_INTENT = "settlement_intent"
    POLICY_STATE = "policy_state"


class RecoveryPlane(StrEnum):
    """Partition plane is fail-closed authority. Frontier plane is a scan journal."""

    PARTITION = "partition"
    FRONTIER = "frontier"


class RecoveryAction(StrEnum):
    REPLAY = "replay"
    REBUILD = "rebuild"
    DISCARD_SNAPSHOT = "discard_snapshot"
    STALE_CONTINUE = "stale_continue"
    IGNORE_ORPHAN = "ignore_orphan"
    IDEMPOTENT_NOOP = "idempotent_noop"
    IDEMPOTENT_REPLAY = "idempotent_replay"
    FRESH = "fresh"
    FAIL_CLOSED = "fail_closed"


class CrashWindow(StrEnum):
    SNAPSHOT_AHEAD_OF_WAL = "snapshot_ahead_of_wal"
    SNAPSHOT_BEHIND_WAL = "snapshot_behind_wal"
    WAL_TRUNCATED_AFTER_SNAPSHOT = "wal_truncated_after_snapshot"
    SNAPSHOT_SEMANTICALLY_OLD = "snapshot_semantically_old"
    SCHEMA_NEWER_THAN_READER = "schema_newer_than_reader"
    SCHEMA_OLDER_THAN_READER = "schema_older_than_reader"
    OUTBOX_WITHOUT_FSM = "outbox_without_fsm"
    FSM_WITHOUT_OUTBOX = "fsm_without_outbox"
    DELIVERY_AHEAD_OF_OUTBOX = "delivery_ahead_of_outbox"
    WAL_COMMITTED_OUTBOX_MISSING = "wal_committed_outbox_missing"
    OUTBOX_APPENDED_DELIVERY_MISSING = "outbox_appended_delivery_missing"
    CRASH_DURING_COMPENSATION = "crash_during_compensation"


class RecoveryPhase(StrEnum):
    UNINITIALIZED = "uninitialized"
    LOAD_SNAPSHOT = "load_snapshot"
    VERIFY_SNAPSHOT = "verify_snapshot"
    LOAD_WAL = "load_wal"
    RECONCILE_SNAPSHOT_WAL = "reconcile_snapshot_wal"
    REPLAY_WAL = "replay_wal"
    RECONSTRUCT_FSM = "reconstruct_fsm"
    RECONCILE_OUTBOX = "reconcile_outbox"
    RECONCILE_DELIVERY = "reconcile_delivery"
    VERIFY_INVARIANTS = "verify_invariants"
    READY = "ready"
    FAIL_CLOSED = "fail_closed"
    FRESH = "fresh"


_TERMINAL_PHASES = frozenset({RecoveryPhase.READY, RecoveryPhase.FAIL_CLOSED, RecoveryPhase.FRESH})

_LEGAL_TRANSITIONS: dict[RecoveryPhase, frozenset[RecoveryPhase]] = {
    RecoveryPhase.UNINITIALIZED: frozenset(
        {
            RecoveryPhase.LOAD_SNAPSHOT,
            RecoveryPhase.LOAD_WAL,
            RecoveryPhase.FRESH,
            RecoveryPhase.FAIL_CLOSED,
        }
    ),
    RecoveryPhase.LOAD_SNAPSHOT: frozenset(
        {
            RecoveryPhase.VERIFY_SNAPSHOT,
            RecoveryPhase.LOAD_WAL,
            RecoveryPhase.FRESH,
            RecoveryPhase.FAIL_CLOSED,
        }
    ),
    RecoveryPhase.VERIFY_SNAPSHOT: frozenset(
        {
            RecoveryPhase.LOAD_WAL,
            RecoveryPhase.FRESH,
            RecoveryPhase.FAIL_CLOSED,
        }
    ),
    RecoveryPhase.LOAD_WAL: frozenset(
        {
            RecoveryPhase.RECONCILE_SNAPSHOT_WAL,
            RecoveryPhase.REPLAY_WAL,
            RecoveryPhase.FRESH,
            RecoveryPhase.FAIL_CLOSED,
        }
    ),
    RecoveryPhase.RECONCILE_SNAPSHOT_WAL: frozenset(
        {
            RecoveryPhase.REPLAY_WAL,
            RecoveryPhase.RECONSTRUCT_FSM,
            RecoveryPhase.FRESH,
            RecoveryPhase.FAIL_CLOSED,
        }
    ),
    RecoveryPhase.REPLAY_WAL: frozenset(
        {
            RecoveryPhase.RECONSTRUCT_FSM,
            RecoveryPhase.FAIL_CLOSED,
        }
    ),
    RecoveryPhase.RECONSTRUCT_FSM: frozenset(
        {
            RecoveryPhase.RECONCILE_OUTBOX,
            RecoveryPhase.FAIL_CLOSED,
        }
    ),
    RecoveryPhase.RECONCILE_OUTBOX: frozenset(
        {
            RecoveryPhase.RECONCILE_DELIVERY,
            RecoveryPhase.FAIL_CLOSED,
        }
    ),
    RecoveryPhase.RECONCILE_DELIVERY: frozenset({RecoveryPhase.VERIFY_INVARIANTS}),
    RecoveryPhase.VERIFY_INVARIANTS: frozenset({RecoveryPhase.READY, RecoveryPhase.FAIL_CLOSED}),
    RecoveryPhase.READY: frozenset(),
    RecoveryPhase.FAIL_CLOSED: frozenset(),
    RecoveryPhase.FRESH: frozenset(),
}


class RecoveryProtocolError(RuntimeError):
    """Illegal recovery transition or unreadable durable state (I35)."""


class UnsupportedSchemaError(RecoveryProtocolError):
    """Snapshot schema_version is newer than this reader (I35)."""


@dataclass(frozen=True, slots=True)
class DurableBoundary:
    """Answers the recovery questions for one persistent object."""

    obj: DurableObject
    authoritative_source: str
    reconstructible: bool
    reconstructed_from: str
    deterministic: bool
    idempotent: bool
    snapshot_wal_disagreement: str
    wal_truncated_after_snapshot: str
    snapshot_semantically_old: str
    schema_newer_than_reader: str
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "obj": self.obj.value,
            "authoritative_source": self.authoritative_source,
            "reconstructible": self.reconstructible,
            "reconstructed_from": self.reconstructed_from,
            "deterministic": self.deterministic,
            "idempotent": self.idempotent,
            "snapshot_wal_disagreement": self.snapshot_wal_disagreement,
            "wal_truncated_after_snapshot": self.wal_truncated_after_snapshot,
            "snapshot_semantically_old": self.snapshot_semantically_old,
            "schema_newer_than_reader": self.schema_newer_than_reader,
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class CrashResolution:
    """Declared resolution for one crash / disagreement window."""

    window: CrashWindow
    action: RecoveryAction
    partition_action: RecoveryAction
    frontier_action: RecoveryAction
    reconstructible: bool
    deterministic: bool
    idempotent: bool
    operator_action: str
    notes: str = ""

    def action_for(self, plane: RecoveryPlane | str) -> RecoveryAction:
        key = RecoveryPlane(plane)
        if key is RecoveryPlane.PARTITION:
            return self.partition_action
        return self.frontier_action

    def to_dict(self) -> dict[str, Any]:
        return {
            "window": self.window.value,
            "action": self.action.value,
            "partition_action": self.partition_action.value,
            "frontier_action": self.frontier_action.value,
            "reconstructible": self.reconstructible,
            "deterministic": self.deterministic,
            "idempotent": self.idempotent,
            "operator_action": self.operator_action,
            "notes": self.notes,
        }


DURABLE_BOUNDARIES: dict[DurableObject, DurableBoundary] = {
    DurableObject.PARTITION_WAL: DurableBoundary(
        obj=DurableObject.PARTITION_WAL,
        authoritative_source="itself (L0 Raft log, CRC-64 fail-closed)",
        reconstructible=False,
        reconstructed_from="not reconstructible — it is the source",
        deterministic=True,
        idempotent=True,
        snapshot_wal_disagreement="WAL wins. Discard snapshot.",
        wal_truncated_after_snapshot="FAIL_CLOSED. Do not invent missing committed entries.",
        snapshot_semantically_old="Replay exclusive post-snapshot committed entries (I16).",
        schema_newer_than_reader="FAIL_CLOSED. Do not down-migrate PartitionWAL records.",
        notes="I15: CRC mismatch aborts with zero mutations.",
    ),
    DurableObject.PARTITION_FSM: DurableBoundary(
        obj=DurableObject.PARTITION_FSM,
        authoritative_source="PartitionWAL committed entries",
        reconstructible=True,
        reconstructed_from="sequential FSM.Apply of committed PartitionWAL (I9/I16)",
        deterministic=True,
        idempotent=True,
        snapshot_wal_disagreement="Reconstruct FSM from WAL. Snapshot is a projection.",
        wal_truncated_after_snapshot="FAIL_CLOSED. FSM cannot be completed from a snapshot.",
        snapshot_semantically_old="Replay WAL from snapshot index + 1.",
        schema_newer_than_reader="FAIL_CLOSED. Unknown command schema is not applied.",
        notes="In-memory only. Never an independent restore source (Axiom 1).",
    ),
    DurableObject.FRONTIER_WAL: DurableBoundary(
        obj=DurableObject.FRONTIER_WAL,
        authoritative_source="itself (scan journal AOF / Redis stream)",
        reconstructible=False,
        reconstructed_from="not reconstructible — it is the scan-journal source",
        deterministic=True,
        idempotent=True,
        snapshot_wal_disagreement="Replay exclusive post-snapshot CRDT deltas.",
        wal_truncated_after_snapshot=(
            "STALE_CONTINUE from the snapshot projection. Do not invent missing journal ids."
        ),
        snapshot_semantically_old="Expected. Replay journal after snapshot cursor.",
        schema_newer_than_reader="Refuse the journal record; keep prior reconstructed state.",
        notes="Skip-unless-high-corruption is intentional for this journal, not PartitionWAL.",
    ),
    DurableObject.CHECKPOINT_SNAPSHOT: DurableBoundary(
        obj=DurableObject.CHECKPOINT_SNAPSHOT,
        authoritative_source="none — L3 projection cache",
        reconstructible=True,
        reconstructed_from="FrontierWAL CRDT + PartitionWAL replay + context snapshots",
        deterministic=True,
        idempotent=True,
        snapshot_wal_disagreement="WAL / FSM wins. Discard or ignore the snapshot.",
        wal_truncated_after_snapshot=(
            "Frontier: keep as STALE projection. Partition: FAIL_CLOSED."
        ),
        snapshot_semantically_old="Valid cache. Replay WAL on top (I21).",
        schema_newer_than_reader="FAIL_CLOSED for this snapshot. Try another, else FRESH.",
        notes="verify_checkpoint_against_fsm rejects index/hash ahead of FSM.",
    ),
    DurableObject.DURABLE_OUTBOX: DurableBoundary(
        obj=DurableObject.DURABLE_OUTBOX,
        authoritative_source="committed PartitionWAL emitted_events (rebuild key = EventId)",
        reconstructible=True,
        reconstructed_from="CommittedEntry.emitted_events after FSM replay",
        deterministic=True,
        idempotent=True,
        snapshot_wal_disagreement="Not involved. Outbox is rebuilt from committed WAL.",
        wal_truncated_after_snapshot="Rebuild from remaining committed entries only.",
        snapshot_semantically_old="Replay outbox from reconstructed FSM emissions.",
        schema_newer_than_reader="FAIL_CLOSED on the unread event record (I15).",
        notes="Outbox is not authority over FSM. Orphan outbox rows are ignored.",
    ),
    DurableObject.DELIVERY_LEDGER: DurableBoundary(
        obj=DurableObject.DELIVERY_LEDGER,
        authoritative_source="none — process-local cache of DeliveryId",
        reconstructible=True,
        reconstructed_from="empty set; replay dispatch from outbox EventIds (I32/I33)",
        deterministic=True,
        idempotent=True,
        snapshot_wal_disagreement="Not involved.",
        wal_truncated_after_snapshot="Not involved.",
        snapshot_semantically_old="Not involved.",
        schema_newer_than_reader="Not involved.",
        notes="After crash the ledger is empty. Delivery ahead of outbox is discarded.",
    ),
    DurableObject.GLOBAL_BUDGET: DurableBoundary(
        obj=DurableObject.GLOBAL_BUDGET,
        authoritative_source="PartitionFSM apply of budget commands on P-0000",
        reconstructible=True,
        reconstructed_from="sequential Reserve/Settle/Expire commands in PartitionWAL",
        deterministic=True,
        idempotent=True,
        snapshot_wal_disagreement="Reconstruct from WAL. Do not trust a budget snapshot.",
        wal_truncated_after_snapshot="FAIL_CLOSED. Missing settle/reserve cannot be invented.",
        snapshot_semantically_old="Replay remaining budget commands.",
        schema_newer_than_reader="FAIL_CLOSED.",
        notes="require_conservation() after every mutating rebuild (I5/I26).",
    ),
    DurableObject.SETTLEMENT_INTENT: DurableBoundary(
        obj=DurableObject.SETTLEMENT_INTENT,
        authoritative_source="FrontierWAL SettlementIntent envelope (wal_id)",
        reconstructible=True,
        reconstructed_from="FrontierWAL records with settlement identity (I33)",
        deterministic=True,
        idempotent=True,
        snapshot_wal_disagreement="Intent in WAL wins over ctx.result projection.",
        wal_truncated_after_snapshot="Missing intent is treated as never committed (I31).",
        snapshot_semantically_old="Replay intents after snapshot cursor.",
        schema_newer_than_reader="Refuse the unread intent; do not project it.",
        notes="FINDING_CREATED still requires COMMITTED + wal_id (I31).",
    ),
    DurableObject.POLICY_STATE: DurableBoundary(
        obj=DurableObject.POLICY_STATE,
        authoritative_source="PartitionFSM after Promote/RollbackPolicy commands",
        reconstructible=True,
        reconstructed_from="policy commands in PartitionWAL",
        deterministic=True,
        idempotent=True,
        snapshot_wal_disagreement="FSM wins. Tuner cache is not authority.",
        wal_truncated_after_snapshot="FAIL_CLOSED. Do not activate a snapshot policy.",
        snapshot_semantically_old="Replay remaining promote/rollback commands.",
        schema_newer_than_reader="FAIL_CLOSED.",
        notes="PolicyGovernanceGate is fail-closed without the replicated log.",
    ),
}


def _resolution(
    window: CrashWindow,
    *,
    action: RecoveryAction,
    partition: RecoveryAction,
    frontier: RecoveryAction,
    reconstructible: bool,
    deterministic: bool,
    idempotent: bool,
    operator_action: str,
    notes: str = "",
) -> CrashResolution:
    return CrashResolution(
        window=window,
        action=action,
        partition_action=partition,
        frontier_action=frontier,
        reconstructible=reconstructible,
        deterministic=deterministic,
        idempotent=idempotent,
        operator_action=operator_action,
        notes=notes,
    )


CRASH_RESOLUTIONS: dict[CrashWindow, CrashResolution] = {
    CrashWindow.SNAPSHOT_AHEAD_OF_WAL: _resolution(
        CrashWindow.SNAPSHOT_AHEAD_OF_WAL,
        action=RecoveryAction.DISCARD_SNAPSHOT,
        partition=RecoveryAction.FAIL_CLOSED,
        frontier=RecoveryAction.DISCARD_SNAPSHOT,
        reconstructible=True,
        deterministic=True,
        idempotent=True,
        operator_action="Discard the snapshot. Partition plane: stop. Frontier: recover remaining journal or FRESH.",
        notes="A snapshot claiming a future log index / missing wal_id is not authority.",
    ),
    CrashWindow.SNAPSHOT_BEHIND_WAL: _resolution(
        CrashWindow.SNAPSHOT_BEHIND_WAL,
        action=RecoveryAction.REPLAY,
        partition=RecoveryAction.REPLAY,
        frontier=RecoveryAction.REPLAY,
        reconstructible=True,
        deterministic=True,
        idempotent=True,
        operator_action="None. Replay exclusive post-snapshot committed records.",
        notes="The common, healthy restart path (I16/I21).",
    ),
    CrashWindow.WAL_TRUNCATED_AFTER_SNAPSHOT: _resolution(
        CrashWindow.WAL_TRUNCATED_AFTER_SNAPSHOT,
        action=RecoveryAction.FAIL_CLOSED,
        partition=RecoveryAction.FAIL_CLOSED,
        frontier=RecoveryAction.STALE_CONTINUE,
        reconstructible=False,
        deterministic=True,
        idempotent=True,
        operator_action="Partition: restore certified WAL or refuse boot. Frontier: continue from STALE snapshot, do not invent journal ids.",
        notes="Missing committed tail cannot be reconstructed.",
    ),
    CrashWindow.SNAPSHOT_SEMANTICALLY_OLD: _resolution(
        CrashWindow.SNAPSHOT_SEMANTICALLY_OLD,
        action=RecoveryAction.REPLAY,
        partition=RecoveryAction.REPLAY,
        frontier=RecoveryAction.REPLAY,
        reconstructible=True,
        deterministic=True,
        idempotent=True,
        operator_action="None. Snapshot is a valid cache; WAL is newer.",
        notes="Same action as SNAPSHOT_BEHIND_WAL; named so operators can see 'old but valid'.",
    ),
    CrashWindow.SCHEMA_NEWER_THAN_READER: _resolution(
        CrashWindow.SCHEMA_NEWER_THAN_READER,
        action=RecoveryAction.FAIL_CLOSED,
        partition=RecoveryAction.FAIL_CLOSED,
        frontier=RecoveryAction.FRESH,
        reconstructible=False,
        deterministic=True,
        idempotent=True,
        operator_action="Upgrade the reader. Do not down-migrate. Frontier may start a fresh run.",
        notes="Unknown future schema is not interpreted.",
    ),
    CrashWindow.SCHEMA_OLDER_THAN_READER: _resolution(
        CrashWindow.SCHEMA_OLDER_THAN_READER,
        action=RecoveryAction.REPLAY,
        partition=RecoveryAction.REPLAY,
        frontier=RecoveryAction.REPLAY,
        reconstructible=True,
        deterministic=True,
        idempotent=True,
        operator_action="None. Apply the registered forward upcaster / checkpoint migration.",
        notes="v1→v2 checkpoint migration and CommandEnvelope upcast already exist.",
    ),
    CrashWindow.OUTBOX_WITHOUT_FSM: _resolution(
        CrashWindow.OUTBOX_WITHOUT_FSM,
        action=RecoveryAction.IGNORE_ORPHAN,
        partition=RecoveryAction.IGNORE_ORPHAN,
        frontier=RecoveryAction.IGNORE_ORPHAN,
        reconstructible=True,
        deterministic=True,
        idempotent=True,
        operator_action="Rebuild FSM from PartitionWAL. Leave orphan outbox rows in place; do not apply them.",
        notes="Outbox is not authority. Orphans stay append-only and are ignored.",
    ),
    CrashWindow.FSM_WITHOUT_OUTBOX: _resolution(
        CrashWindow.FSM_WITHOUT_OUTBOX,
        action=RecoveryAction.REBUILD,
        partition=RecoveryAction.REBUILD,
        frontier=RecoveryAction.REBUILD,
        reconstructible=True,
        deterministic=True,
        idempotent=True,
        operator_action="None. Rebuild outbox from CommittedEntry.emitted_events (EventId dedupe).",
        notes="Crash between WAL commit / FSM apply and outbox append.",
    ),
    CrashWindow.DELIVERY_AHEAD_OF_OUTBOX: _resolution(
        CrashWindow.DELIVERY_AHEAD_OF_OUTBOX,
        action=RecoveryAction.DISCARD_SNAPSHOT,
        partition=RecoveryAction.DISCARD_SNAPSHOT,
        frontier=RecoveryAction.DISCARD_SNAPSHOT,
        reconstructible=True,
        deterministic=True,
        idempotent=True,
        operator_action="Discard DeliveryIds whose EventId is not in the outbox. Replay from outbox.",
        notes="DeliveryLedger is a cache. Ahead-of-outbox can only be an in-process bug.",
    ),
    CrashWindow.WAL_COMMITTED_OUTBOX_MISSING: _resolution(
        CrashWindow.WAL_COMMITTED_OUTBOX_MISSING,
        action=RecoveryAction.REBUILD,
        partition=RecoveryAction.REBUILD,
        frontier=RecoveryAction.REBUILD,
        reconstructible=True,
        deterministic=True,
        idempotent=True,
        operator_action="None. Same as FSM_WITHOUT_OUTBOX. Do not roll back the WAL (I32).",
        notes="Authoritative commit already happened; outbox is reconstructed.",
    ),
    CrashWindow.OUTBOX_APPENDED_DELIVERY_MISSING: _resolution(
        CrashWindow.OUTBOX_APPENDED_DELIVERY_MISSING,
        action=RecoveryAction.IDEMPOTENT_REPLAY,
        partition=RecoveryAction.IDEMPOTENT_REPLAY,
        frontier=RecoveryAction.IDEMPOTENT_REPLAY,
        reconstructible=True,
        deterministic=True,
        idempotent=True,
        operator_action="None. Replay dispatch. DeliveryId not recorded on failure (I32/I33).",
        notes="EventBus failure ≠ authoritative failure.",
    ),
    CrashWindow.CRASH_DURING_COMPENSATION: _resolution(
        CrashWindow.CRASH_DURING_COMPENSATION,
        action=RecoveryAction.IDEMPOTENT_REPLAY,
        partition=RecoveryAction.IDEMPOTENT_REPLAY,
        frontier=RecoveryAction.IDEMPOTENT_REPLAY,
        reconstructible=True,
        deterministic=True,
        idempotent=True,
        operator_action="Replay compensate_sublease. Terminal COMPENSATED/CONSUMED/EXPIRED is a no-op (I28).",
        notes="Do not panic-compensate on step-down (I34 AUTHORITY_LOSS).",
    ),
}


@dataclass(frozen=True, slots=True)
class ObservedDurableState:
    """Inputs the protocol can see without performing I/O itself."""

    plane: RecoveryPlane = RecoveryPlane.FRONTIER
    snapshot_present: bool = False
    wal_present: bool = False
    snapshot_schema_version: int = 0
    reader_schema_version: int = READER_SCHEMA_VERSION
    snapshot_log_index: int = 0
    wal_commit_index: int = 0
    snapshot_last_wal_id: str = ""
    wal_ids: frozenset[str] = field(default_factory=frozenset)
    wal_truncated_after_snapshot: bool = False
    snapshot_semantically_old: bool = False
    fsm_applied_index: int = 0
    fsm_event_ids: frozenset[str] = field(default_factory=frozenset)
    outbox_event_ids: frozenset[str] = field(default_factory=frozenset)
    delivered_event_ids: frozenset[str] = field(default_factory=frozenset)
    compensation_in_progress: bool = False
    compensation_lease_status: str = ""


@dataclass(frozen=True, slots=True)
class RecoveryVerdict:
    """Result of walking the recovery state machine."""

    phase: RecoveryPhase
    plane: RecoveryPlane
    action: RecoveryAction
    windows: tuple[CrashWindow, ...]
    snapshot_stale: bool
    discard_snapshot: bool
    rebuild_outbox: bool
    replay_delivery: bool
    orphan_outbox_ids: tuple[str, ...]
    discarded_delivery_ids: tuple[str, ...]
    path: tuple[RecoveryPhase, ...]
    notes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "plane": self.plane.value,
            "action": self.action.value,
            "windows": [w.value for w in self.windows],
            "snapshot_stale": self.snapshot_stale,
            "discard_snapshot": self.discard_snapshot,
            "rebuild_outbox": self.rebuild_outbox,
            "replay_delivery": self.replay_delivery,
            "orphan_outbox_ids": list(self.orphan_outbox_ids),
            "discarded_delivery_ids": list(self.discarded_delivery_ids),
            "path": [p.value for p in self.path],
            "notes": list(self.notes),
        }


class RecoverySession:
    """Enforces legal I35 phase transitions."""

    def __init__(self) -> None:
        self.phase = RecoveryPhase.UNINITIALIZED
        self.path: list[RecoveryPhase] = [RecoveryPhase.UNINITIALIZED]

    def advance(self, nxt: RecoveryPhase) -> RecoveryPhase:
        if nxt is self.phase:
            return self.phase
        allowed = _LEGAL_TRANSITIONS[self.phase]
        if nxt not in allowed:
            raise RecoveryProtocolError(
                f"{I35_RECOVERY_PROTOCOL}: illegal transition {self.phase.value} → {nxt.value}"
            )
        self.phase = nxt
        self.path.append(nxt)
        return self.phase

    @property
    def terminal(self) -> bool:
        return self.phase in _TERMINAL_PHASES


def boundary_for(obj: DurableObject | str) -> DurableBoundary:
    return DURABLE_BOUNDARIES[DurableObject(obj)]


def resolution_for(window: CrashWindow | str) -> CrashResolution:
    return CRASH_RESOLUTIONS[CrashWindow(window)]


def assert_schema_readable(
    schema_version: int,
    *,
    reader_version: int = READER_SCHEMA_VERSION,
) -> None:
    """I35: a snapshot newer than this reader is unreadable."""
    version = int(schema_version)
    if version > int(reader_version):
        raise UnsupportedSchemaError(
            f"{I35_RECOVERY_PROTOCOL}: schema_version {version} is newer than "
            f"reader {reader_version}; refuse to interpret"
        )


def detect_snapshot_wal_window(observed: ObservedDurableState) -> CrashWindow | None:
    """Classify snapshot ↔ WAL disagreement. None if there is no snapshot."""
    if not observed.snapshot_present:
        return None
    if observed.snapshot_schema_version > observed.reader_schema_version:
        return CrashWindow.SCHEMA_NEWER_THAN_READER
    if (
        0 < observed.snapshot_schema_version < observed.reader_schema_version
        and observed.snapshot_schema_version > 0
    ):
        # Older is readable via migration; still classify if that is the only signal.
        pass
    if observed.wal_truncated_after_snapshot:
        return CrashWindow.WAL_TRUNCATED_AFTER_SNAPSHOT
    cursor = str(observed.snapshot_last_wal_id or "").strip()
    if cursor and observed.wal_ids and cursor not in observed.wal_ids:
        return CrashWindow.SNAPSHOT_AHEAD_OF_WAL
    if observed.snapshot_log_index > observed.wal_commit_index:
        return CrashWindow.SNAPSHOT_AHEAD_OF_WAL
    if observed.snapshot_semantically_old:
        return CrashWindow.SNAPSHOT_SEMANTICALLY_OLD
    if observed.wal_present and (
        observed.wal_commit_index > observed.snapshot_log_index
        or (observed.wal_ids and cursor and cursor in observed.wal_ids)
        or observed.wal_commit_index > 0
    ):
        return CrashWindow.SNAPSHOT_BEHIND_WAL
    if observed.snapshot_schema_version and (
        observed.snapshot_schema_version < observed.reader_schema_version
    ):
        return CrashWindow.SCHEMA_OLDER_THAN_READER
    if observed.wal_present:
        return CrashWindow.SNAPSHOT_BEHIND_WAL
    return CrashWindow.SNAPSHOT_SEMANTICALLY_OLD


def detect_outbox_window(observed: ObservedDurableState) -> CrashWindow | None:
    fsm_ids = set(observed.fsm_event_ids)
    outbox_ids = set(observed.outbox_event_ids)
    if outbox_ids - fsm_ids and not fsm_ids and observed.fsm_applied_index == 0:
        return CrashWindow.OUTBOX_WITHOUT_FSM
    if fsm_ids - outbox_ids:
        return CrashWindow.FSM_WITHOUT_OUTBOX
    if outbox_ids - fsm_ids:
        return CrashWindow.OUTBOX_WITHOUT_FSM
    if observed.wal_present and observed.fsm_applied_index > 0 and not outbox_ids and fsm_ids:
        return CrashWindow.WAL_COMMITTED_OUTBOX_MISSING
    return None


def detect_delivery_window(observed: ObservedDurableState) -> CrashWindow | None:
    outbox_ids = set(observed.outbox_event_ids)
    delivered = set(observed.delivered_event_ids)
    if delivered - outbox_ids:
        return CrashWindow.DELIVERY_AHEAD_OF_OUTBOX
    if outbox_ids - delivered:
        return CrashWindow.OUTBOX_APPENDED_DELIVERY_MISSING
    return None


def resolve_compensation_crash(lease_status: str) -> RecoveryAction:
    """I28 + I35: compensation replay is idempotent; CONSUMED cannot compensate."""
    status = str(lease_status or "").strip().lower()
    if status in {"compensated", "consumed", "expired", "closed"}:
        return RecoveryAction.IDEMPOTENT_NOOP
    if status in {"reserved", "issued", "requested", ""}:
        return RecoveryAction.IDEMPOTENT_REPLAY
    return RecoveryAction.FAIL_CLOSED


def orphan_outbox_ids(
    fsm_event_ids: Iterable[str], outbox_event_ids: Iterable[str]
) -> tuple[str, ...]:
    extras = sorted({str(i) for i in outbox_event_ids if i} - {str(i) for i in fsm_event_ids if i})
    return tuple(extras)


def rebuild_outbox_from_committed_entries(entries: Sequence[Any], outbox: Any) -> int:
    """I35 FSM_WITHOUT_OUTBOX: append stored emitted_events; EventId dedupes."""
    if outbox is None or not hasattr(outbox, "append_events"):
        return 0
    appended = 0
    for entry in entries:
        events = getattr(entry, "emitted_events", ()) or ()
        if not events:
            continue
        appended += int(outbox.append_events(events, sync=True) or 0)
    return appended


def run_recovery_protocol(observed: ObservedDurableState) -> RecoveryVerdict:
    """Walk the I35 state machine against an observation and return a verdict."""
    session = RecoverySession()
    plane = RecoveryPlane(observed.plane)
    windows: list[CrashWindow] = []
    notes: list[str] = []
    snapshot_stale = False
    discard_snapshot = False
    rebuild_outbox = False
    replay_delivery = False
    orphans: tuple[str, ...] = ()
    discarded_delivery: tuple[str, ...] = ()

    def _fail(note: str, action: RecoveryAction = RecoveryAction.FAIL_CLOSED) -> RecoveryVerdict:
        session.advance(RecoveryPhase.FAIL_CLOSED)
        notes.append(note)
        return RecoveryVerdict(
            phase=RecoveryPhase.FAIL_CLOSED,
            plane=plane,
            action=action,
            windows=tuple(windows),
            snapshot_stale=snapshot_stale,
            discard_snapshot=True,
            rebuild_outbox=False,
            replay_delivery=False,
            orphan_outbox_ids=orphans,
            discarded_delivery_ids=discarded_delivery,
            path=tuple(session.path),
            notes=tuple(notes),
        )

    def _fresh(note: str) -> RecoveryVerdict:
        session.advance(RecoveryPhase.FRESH)
        notes.append(note)
        return RecoveryVerdict(
            phase=RecoveryPhase.FRESH,
            plane=plane,
            action=RecoveryAction.FRESH,
            windows=tuple(windows),
            snapshot_stale=False,
            discard_snapshot=True,
            rebuild_outbox=False,
            replay_delivery=False,
            orphan_outbox_ids=(),
            discarded_delivery_ids=(),
            path=tuple(session.path),
            notes=tuple(notes),
        )

    if not observed.snapshot_present and not observed.wal_present:
        return _fresh("no snapshot and no WAL")

    if observed.snapshot_present:
        session.advance(RecoveryPhase.LOAD_SNAPSHOT)
        session.advance(RecoveryPhase.VERIFY_SNAPSHOT)
        if observed.snapshot_schema_version > observed.reader_schema_version:
            windows.append(CrashWindow.SCHEMA_NEWER_THAN_READER)
            action = resolution_for(CrashWindow.SCHEMA_NEWER_THAN_READER).action_for(plane)
            if action is RecoveryAction.FRESH:
                return _fresh("schema newer than reader")
            return _fail("schema newer than reader")
        if 0 < observed.snapshot_schema_version < observed.reader_schema_version:
            windows.append(CrashWindow.SCHEMA_OLDER_THAN_READER)
            notes.append("forward-migrate snapshot schema")
        session.advance(RecoveryPhase.LOAD_WAL)
    else:
        session.advance(RecoveryPhase.LOAD_WAL)

    session.advance(RecoveryPhase.RECONCILE_SNAPSHOT_WAL)
    snap_window = detect_snapshot_wal_window(observed) if observed.snapshot_present else None
    if snap_window is not None:
        if snap_window not in windows:
            windows.append(snap_window)
        action = resolution_for(snap_window).action_for(plane)
        if action is RecoveryAction.FAIL_CLOSED:
            return _fail(f"snapshot/WAL window {snap_window.value}")
        if action is RecoveryAction.FRESH:
            return _fresh(f"snapshot/WAL window {snap_window.value}")
        if action is RecoveryAction.DISCARD_SNAPSHOT:
            discard_snapshot = True
            notes.append(f"discard snapshot ({snap_window.value})")
        if action is RecoveryAction.STALE_CONTINUE:
            snapshot_stale = True
            notes.append("snapshot kept as STALE projection")
        if action is RecoveryAction.REPLAY:
            notes.append(f"replay WAL after snapshot ({snap_window.value})")

    session.advance(RecoveryPhase.REPLAY_WAL)
    session.advance(RecoveryPhase.RECONSTRUCT_FSM)
    session.advance(RecoveryPhase.RECONCILE_OUTBOX)

    outbox_window = detect_outbox_window(observed)
    if outbox_window is not None:
        windows.append(outbox_window)
        action = resolution_for(outbox_window).action_for(plane)
        if action is RecoveryAction.FAIL_CLOSED:
            return _fail(f"outbox window {outbox_window.value}")
        if action is RecoveryAction.REBUILD:
            rebuild_outbox = True
            notes.append("rebuild outbox from committed emitted_events")
        if action is RecoveryAction.IGNORE_ORPHAN:
            orphans = orphan_outbox_ids(observed.fsm_event_ids, observed.outbox_event_ids)
            notes.append(f"ignore {len(orphans)} orphan outbox event(s)")

    session.advance(RecoveryPhase.RECONCILE_DELIVERY)
    delivery_window = detect_delivery_window(observed)
    if delivery_window is not None:
        windows.append(delivery_window)
        if delivery_window is CrashWindow.DELIVERY_AHEAD_OF_OUTBOX:
            discarded_delivery = tuple(
                sorted(set(observed.delivered_ids) - set(observed.outbox_event_ids))
            )
            notes.append("discard delivery ids not in outbox")
            replay_delivery = True
        else:
            replay_delivery = True
            notes.append("replay dispatch for undelivered outbox events")

    session.advance(RecoveryPhase.VERIFY_INVARIANTS)
    if observed.compensation_in_progress:
        windows.append(CrashWindow.CRASH_DURING_COMPENSATION)
        comp = resolve_compensation_crash(observed.compensation_lease_status)
        if comp is RecoveryAction.FAIL_CLOSED:
            return _fail("compensation crash on non-compensatable lease")
        notes.append(f"compensation crash → {comp.value}")

    session.advance(RecoveryPhase.READY)
    final_action = RecoveryAction.STALE_CONTINUE if snapshot_stale else RecoveryAction.REPLAY
    if discard_snapshot and not observed.wal_present:
        # Should have gone FRESH already; keep READY only when WAL remains.
        final_action = RecoveryAction.DISCARD_SNAPSHOT
    return RecoveryVerdict(
        phase=RecoveryPhase.READY,
        plane=plane,
        action=final_action,
        windows=tuple(windows),
        snapshot_stale=snapshot_stale,
        discard_snapshot=discard_snapshot,
        rebuild_outbox=rebuild_outbox,
        replay_delivery=replay_delivery,
        orphan_outbox_ids=orphans,
        discarded_delivery_ids=discarded_delivery,
        path=tuple(session.path),
        notes=tuple(notes),
    )


def durable_catalog() -> tuple[dict[str, Any], ...]:
    return tuple(DURABLE_BOUNDARIES[obj].to_dict() for obj in DurableObject)


def crash_catalog() -> tuple[dict[str, Any], ...]:
    return tuple(CRASH_RESOLUTIONS[window].to_dict() for window in CrashWindow)


__all__ = [
    "CRASH_RESOLUTIONS",
    "DURABLE_BOUNDARIES",
    "CrashResolution",
    "CrashWindow",
    "DurableBoundary",
    "DurableObject",
    "I35_RECOVERY_PROTOCOL",
    "ObservedDurableState",
    "READER_SCHEMA_VERSION",
    "RecoveryAction",
    "RecoveryPhase",
    "RecoveryPlane",
    "RecoveryProtocolError",
    "RecoverySession",
    "RecoveryVerdict",
    "UnsupportedSchemaError",
    "assert_schema_readable",
    "boundary_for",
    "crash_catalog",
    "detect_delivery_window",
    "detect_outbox_window",
    "detect_snapshot_wal_window",
    "durable_catalog",
    "orphan_outbox_ids",
    "rebuild_outbox_from_committed_entries",
    "resolution_for",
    "resolve_compensation_crash",
    "run_recovery_protocol",
]
