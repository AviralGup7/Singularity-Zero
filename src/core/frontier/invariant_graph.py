"""Invariant dependency / proof graph (I22, I28, I30–I37).

Cross-subsystem invariants used to live as separate modules. A recovery
walk could satisfy I35 while reconstructed tickets failed I30 / I31, and
an I37 activate could succeed while an I30-invalid ticket was treated as
live. This module is the machine-checkable proof:

    I22 clock admission
          │
          ▼
    I30 authorization causality
          │
          ├──────────────┐
          ▼              ▼
    I33 causal IDs      I28 budget/lease
          │              │
          ▼              ▼
    I31 settlement ───► durable WAL
          │
          ▼
    I32 durable outbox
          │
          ▼
    I34 failure semantics
          │
          ▼
    I35 recovery
          │
          ▼
    I36 region ──► I37 transfer (also depends on I30)

Every node names what it requires, guarantees, and invalidates, plus
recovery / concurrency / authority dependencies. Every edge is
bidirectional: a forward statement and the reverse assumption the
downstream invariant makes about the upstream one. That catches
"I31 is locally correct but its assumptions about I28 are false."

Runtime gates consult the graph: I35 VERIFY_INVARIANTS fail-closes on a
prerequisite or reverse-assumption violation; I37 activate refuses to
resurrect an I30-invalid ticket.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import SimpleNamespace
from typing import Any

from src.core.frontier.causal_identity import (
    CAUSAL_CHAIN,
    CausalIdentityError,
    assert_causal_identity_chain,
)
from src.core.frontier.global_invariants import (
    AuthorizationCausalityError,
    SettlementCausalityError,
    assert_authorization_causality,
    assert_settlement_causality,
)

PROOF_GRAPH_ID = "PROOF"


class InvariantId(StrEnum):
    I22 = "I22"
    I28 = "I28"
    I30 = "I30"
    I31 = "I31"
    I32 = "I32"
    I33 = "I33"
    I34 = "I34"
    I35 = "I35"
    I36 = "I36"
    I37 = "I37"


class ProofGraphError(PermissionError):
    """Recovered or transferred state violates a prerequisite invariant."""

    def __init__(self, message: str, *, invariant: str = PROOF_GRAPH_ID) -> None:
        super().__init__(message)
        self.invariant = invariant


@dataclass(frozen=True, slots=True)
class InvariantEdge:
    """One directed proof edge with the reverse assumption it encodes."""

    src: InvariantId
    dst: InvariantId
    statement: str
    reverse_assumption: str
    invalidates: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src.value,
            "dst": self.dst.value,
            "statement": self.statement,
            "reverse_assumption": self.reverse_assumption,
            "invalidates": self.invalidates,
        }


@dataclass(frozen=True, slots=True)
class InvariantClaim:
    """What one invariant guarantees, and what a violation of it invalidates."""

    guarantees: str
    invalidates: str
    recovery_dependency: str
    concurrency_dependency: str
    authority_dependency: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "guarantees": self.guarantees,
            "invalidates": self.invalidates,
            "recovery_dependency": self.recovery_dependency,
            "concurrency_dependency": self.concurrency_dependency,
            "authority_dependency": self.authority_dependency,
        }


@dataclass(frozen=True, slots=True)
class InvariantNode:
    """One row of the architecture proof graph."""

    id: InvariantId
    name: str
    prerequisites: tuple[InvariantId, ...]
    protects: str
    transitions: str
    crash_windows: tuple[str, ...]
    concurrency_windows: tuple[str, ...]
    recovery_rule: str
    tests: tuple[str, ...]
    module: str
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.id.value,
            "name": self.name,
            "requires": [p.value for p in self.prerequisites],
            "prerequisites": [p.value for p in self.prerequisites],
            "protects": self.protects,
            "transitions": self.transitions,
            "crash_windows": list(self.crash_windows),
            "concurrency_windows": list(self.concurrency_windows),
            "recovery_rule": self.recovery_rule,
            "tests": list(self.tests),
            "module": self.module,
            "notes": self.notes,
        }
        claim = INVARIANT_CLAIMS.get(self.id)
        if claim is not None:
            payload.update(claim.to_dict())
        return payload


def _node(
    inv: InvariantId,
    *,
    name: str,
    prerequisites: tuple[InvariantId, ...] = (),
    protects: str,
    transitions: str,
    crash_windows: tuple[str, ...],
    concurrency_windows: tuple[str, ...],
    recovery_rule: str,
    tests: tuple[str, ...],
    module: str,
    notes: str = "",
) -> InvariantNode:
    return InvariantNode(
        id=inv,
        name=name,
        prerequisites=prerequisites,
        protects=protects,
        transitions=transitions,
        crash_windows=crash_windows,
        concurrency_windows=concurrency_windows,
        recovery_rule=recovery_rule,
        tests=tests,
        module=module,
        notes=notes,
    )


INVARIANT_GRAPH: dict[InvariantId, InvariantNode] = {
    InvariantId.I22: _node(
        InvariantId.I22,
        name="clock admission",
        prerequisites=(),
        protects="CommandEnvelope.created_at_unix admitted onto PartitionWAL",
        transitions="proposal → admission skew gate → local WAL persist (FSM stays clock-free)",
        crash_windows=("command timestamp in the future of admission clock",),
        concurrency_windows=("two proposers with skewed clocks racing AppendEntries",),
        recovery_rule="Refuse the command at admission. Do not apply. Replay uses committed timestamps only.",
        tests=(
            "tests/unit/test_formal_invariants.py",
            "tests/unit/core/test_invariant_graph.py",
        ),
        module="src/core/frontier/replicated_log.py",
        notes="±10s future drift, −5s backward regression. PartitionFSM never reads time.time().",
    ),
    InvariantId.I30: _node(
        InvariantId.I30,
        name="authorization causality",
        prerequisites=(InvariantId.I22,),
        protects="AuthorizedExecutionTicket (scope, reservation, revision, command_id)",
        transitions="ExecutionRequest → reserve_with_identity → ticket; consume is single-use",
        crash_windows=("crash between reserve and ticket issue", "ticket restored from snapshot"),
        concurrency_windows=("two workers consuming the same ticket_id",),
        recovery_rule="A reconstructed ticket that fails I30 is not authorized. I35 FAIL_CLOSED.",
        tests=(
            "tests/unit/core/test_global_invariants.py",
            "tests/unit/core/test_invariant_graph.py",
        ),
        module="src/core/frontier/global_invariants.py",
        notes="Self-attested tickets are ignored. Consume also checks the live I37 revision.",
    ),
    InvariantId.I28: _node(
        InvariantId.I28,
        name="budget / lease state",
        prerequisites=(InvariantId.I30,),
        protects="LeaseStatus on GlobalSubLease and HuntBudget reservations",
        transitions="RESERVED → ACTIVE → CONSUMED|EXPIRED; RESERVED|EXPIRED → COMPENSATED",
        crash_windows=("crash_during_compensation",),
        concurrency_windows=("reserve vs settle on the same sublease_id",),
        recovery_rule="Idempotent compensate_sublease replay. CONSUMED cannot compensate. EXPIRED is not TERMINAL.",
        tests=(
            "tests/unit/core/test_lease_status.py",
            "tests/unit/test_formal_invariants.py",
        ),
        module="src/core/frontier/lease_status.py",
        notes="Ticket budget_reservation_id is the I30 binding into this ledger.",
    ),
    InvariantId.I33: _node(
        InvariantId.I33,
        name="causal identity chain",
        prerequisites=(InvariantId.I30,),
        protects="CommandId → ExecutionId → AttemptId → SettlementId → WalId → EventId → DeliveryId",
        transitions="FAILED attempt does not close execution_id; retry mints a new AttemptId",
        crash_windows=("crash between WAL commit and EventId mint",),
        concurrency_windows=("two retries of the same execution_id",),
        recovery_rule="Rebuild ids from parents. A non-empty child without ancestors is illegal.",
        tests=("tests/unit/core/test_causal_identity.py",),
        module="src/core/frontier/causal_identity.py",
    ),
    InvariantId.I31: _node(
        InvariantId.I31,
        name="settlement causality",
        prerequisites=(InvariantId.I33, InvariantId.I28),
        protects="FINDING_CREATED / SettlementIntent COMMITTED with nonempty wal_id",
        transitions="StageOutput → settle_stage_output → COMMITTED|REJECTED|DEDUPLICATED",
        crash_windows=("wal_truncated_after_snapshot missing intent",),
        concurrency_windows=("two settlers of the same attempt_id",),
        recovery_rule="Missing intent is never committed. Do not emit FINDING_CREATED without wal_id.",
        tests=(
            "tests/unit/core/test_global_invariants.py",
            "tests/unit/core/test_atlas_holes.py",
        ),
        module="src/core/frontier/global_invariants.py",
        notes="HMAC settlement receipt is the authority bit; a boolean authoritative=True is ignored.",
    ),
    InvariantId.I32: _node(
        InvariantId.I32,
        name="durable outbox / EventBus non-authority",
        prerequisites=(InvariantId.I31,),
        protects="DurableOutbox EventId; DeliveryLedger DeliveryId; in-process EventBus",
        transitions="WAL commit → outbox append → HMAC receipt → bus notify",
        crash_windows=(
            "fsm_without_outbox",
            "outbox_without_fsm",
            "outbox_appended_delivery_missing",
            "delivery_ahead_of_outbox",
        ),
        concurrency_windows=("bus handler vs outbox append failure",),
        recovery_rule="Outbox append fail → do not emit. Bus fail → retry dispatch, never rollback WAL.",
        tests=(
            "tests/unit/core/test_eventbus_guarantees.py",
            "tests/unit/core/test_global_invariants.py",
        ),
        module="src/core/frontier/event_delivery.py",
    ),
    InvariantId.I34: _node(
        InvariantId.I34,
        name="failure recovery semantics",
        prerequisites=(InvariantId.I28, InvariantId.I32),
        protects="RECOVERY_TABLE: retry/rollback/compensate/fail-closed/operator_action",
        transitions="classified failure → exactly one declared policy; must_not forbids drift",
        crash_windows=("wal_corruption", "authority_loss", "fsm_invariant_violation"),
        concurrency_windows=("EventBus failure racing settlement commit",),
        recovery_rule="Call sites consult the table. They must not invent a forbidden action.",
        tests=("tests/unit/core/test_failure_model.py",),
        module="src/core/frontier/failure_model.py",
        notes="EVENT_DELIVERY_FAILURE retries and never rolls back (I32). Budget compensate is I28.",
    ),
    InvariantId.I35: _node(
        InvariantId.I35,
        name="recovery protocol",
        prerequisites=(InvariantId.I32, InvariantId.I34),
        protects="RecoverySession phases; every DurableObject authoritative source",
        transitions="UNINITIALIZED → … → VERIFY_INVARIANTS → READY|FAIL_CLOSED|FRESH",
        crash_windows=(
            "snapshot_ahead_of_wal",
            "wal_truncated_after_snapshot",
            "schema_newer_than_reader",
            "prerequisite_invariant_failed",
        ),
        concurrency_windows=("two RecoveryManagers reconstructing the same run_id",),
        recovery_rule=(
            "VERIFY_INVARIANTS fail-closes if recovered tickets fail I30, recovered "
            "settlements fail I31, identities fail I33, or bus emitted without outbox (I32)."
        ),
        tests=(
            "tests/unit/core/test_recovery_protocol.py",
            "tests/unit/core/test_invariant_graph.py",
        ),
        module="src/core/frontier/recovery_protocol.py",
        notes="Satisfying the phase machine is not enough. Transitive prerequisites must hold.",
    ),
    InvariantId.I36: _node(
        InvariantId.I36,
        name="region consistency",
        prerequisites=(InvariantId.I35,),
        protects="single writer per partition; lease acquire/settle colocation",
        transitions="replica must not propose_and_commit; heal by placement_version not LWW",
        crash_windows=("network_partition", "equal placement_version divergent hashes"),
        concurrency_windows=("lease acquire in A concurrent with settle in B",),
        recovery_rule="Non-leader / minority is fail-closed (I34 AUTHORITY_LOSS). Replay leader WAL (I35).",
        tests=("tests/unit/core/test_region_model.py",),
        module="src/core/frontier/region_model.py",
    ),
    InvariantId.I37: _node(
        InvariantId.I37,
        name="authority transfer fence",
        prerequisites=(InvariantId.I36, InvariantId.I30),
        protects="AuthorityLease phase OWNED|FENCED; AuthorityEpoch/FenceToken/Revision",
        transitions="OWNED → FENCED (nobody writes) → OWNED on pending home",
        crash_windows=("crash after fence before activate", "stale epoch/token after cutover"),
        concurrency_windows=("old home and pending home both believing they are leader",),
        recovery_rule=(
            "Tickets bound to the previous I30 revision cannot be consumed. "
            "Activate refuses to resurrect an I30-invalid ticket."
        ),
        tests=(
            "tests/unit/core/test_authority_transfer.py",
            "tests/unit/core/test_invariant_graph.py",
        ),
        module="src/core/frontier/authority_transfer.py",
        notes="I37 cannot mint I30 authority. Transfer success does not bless a broken ticket.",
    ),
}


def _edge(
    src: InvariantId,
    dst: InvariantId,
    statement: str,
    reverse_assumption: str,
    invalidates: str,
) -> InvariantEdge:
    return InvariantEdge(
        src=src,
        dst=dst,
        statement=statement,
        reverse_assumption=reverse_assumption,
        invalidates=invalidates,
    )


INVARIANT_EDGES: tuple[InvariantEdge, ...] = (
    _edge(
        InvariantId.I22,
        InvariantId.I30,
        "A ticket is admitted only after the command clock passes the skew gate.",
        "I30 assumes I22 that command_id timestamps are admission-monotonic, not wall-clock.",
        "A skewed command cannot mint a live I30 ticket.",
    ),
    _edge(
        InvariantId.I30,
        InvariantId.I33,
        "Every authorized execution receives causally derived identity.",
        "I33 assumes I30 that command_id was minted by authorize, not invented on the identity.",
        "An unauthorized command_id cannot start a causal chain.",
    ),
    _edge(
        InvariantId.I30,
        InvariantId.I28,
        "A budget reservation exists only as the I30 ticket binding.",
        "I28 assumes I30 that budget_reservation_id on the ledger was reserved under a live ticket.",
        "A ticket without a reservation cannot consume or compensate budget.",
    ),
    _edge(
        InvariantId.I33,
        InvariantId.I31,
        "Settlement identity is parent-linked: AttemptId → SettlementId → WalId.",
        "I31 assumes I33 that a COMMITTED wal_id has a complete ancestor chain.",
        "A settlement without ancestors is not COMMITTED.",
    ),
    _edge(
        InvariantId.I28,
        InvariantId.I31,
        "Settlement cannot consume budget outside a valid reservation.",
        "I31 assumes I28 that budget_reservation_id on a COMMITTED settlement is on the ledger.",
        "A COMMITTED settlement with an unknown reservation is not a settlement.",
    ),
    _edge(
        InvariantId.I31,
        InvariantId.I32,
        "Only durably committed settlements may create authoritative events.",
        "I32 assumes I31 that FINDING_CREATED carries COMMITTED + nonempty wal_id.",
        "EventBus cannot author a finding that settlement never committed.",
    ),
    _edge(
        InvariantId.I28,
        InvariantId.I34,
        "Budget inconsistency compensates outstanding leases; it does not roll back WAL.",
        "I34 assumes I28 that EXPIRED is compensatable and CONSUMED is not.",
        "A compensate of CONSUMED is an illegal recovery action.",
    ),
    _edge(
        InvariantId.I32,
        InvariantId.I34,
        "Event delivery failure retries dispatch and never un-commits settlement.",
        "I34 assumes I32 that EventBus is not authority, so rollback is forbidden.",
        "A bus failure cannot become a WAL rollback.",
    ),
    _edge(
        InvariantId.I32,
        InvariantId.I35,
        "Recovery reconstructs delivery from durable authoritative state.",
        "I35 assumes I32 that EventBus and DeliveryLedger are not restore sources.",
        "Replaying bus without outbox cannot READY.",
    ),
    _edge(
        InvariantId.I34,
        InvariantId.I35,
        "VERIFY_INVARIANTS consults the I34 table; it does not invent a recovery action.",
        "I35 assumes I34 that FAIL_CLOSED failures do not retry or roll back.",
        "A recovery walk cannot READY after a fail-closed class.",
    ),
    _edge(
        InvariantId.I35,
        InvariantId.I36,
        "Recovered state must be valid before regional ownership can activate.",
        "I36 assumes I35 that READY means recovered tickets/settlements already held.",
        "A region cannot accept commands on unrecovered or FAIL_CLOSED state.",
    ),
    _edge(
        InvariantId.I36,
        InvariantId.I37,
        "Transfer can only occur through the fenced ownership protocol.",
        "I37 assumes I36 that only the leader home writes while OWNED.",
        "A dual-home activate is not a transfer.",
    ),
    _edge(
        InvariantId.I30,
        InvariantId.I37,
        "A live ticket dies when the fence activates a new authority revision.",
        "I37 assumes I30 that tickets without the quartet were never authorized.",
        "Transfer cannot mint I30 authority or resurrect an invalid ticket.",
    ),
)


INVARIANT_CLAIMS: dict[InvariantId, InvariantClaim] = {
    InvariantId.I22: InvariantClaim(
        guarantees="Admitted commands have non-decreasing created_at within skew bounds.",
        invalidates="Any later mutation that trusts a future or regressing timestamp.",
        recovery_dependency="Replay uses committed timestamps only; never re-admit.",
        concurrency_dependency="Two proposers cannot both pass a regressing clock.",
        authority_dependency="PartitionFSM stays clock-free (Axiom 9).",
    ),
    InvariantId.I30: InvariantClaim(
        guarantees="A live ticket binds scope hash, reservation, revision, and command_id.",
        invalidates="Consume of a ticket missing any binding or unknown reservation.",
        recovery_dependency="Reconstructed tickets must still pass assert_authorization_causality.",
        concurrency_dependency="ticket_id is single-use under the authorizer lock.",
        authority_dependency="Revision must match the live I37 fence.",
    ),
    InvariantId.I28: InvariantClaim(
        guarantees="Lease transitions are the I28 table; EXPIRED is not TERMINAL.",
        invalidates="Compensate of CONSUMED; ACTIVE compensate; invented budget units.",
        recovery_dependency="Compensation crash replays idempotently from RESERVED|EXPIRED.",
        concurrency_dependency="Reserve and settle of the same sublease_id cannot interleave illegally.",
        authority_dependency="Reservations live on P-0000; they do not span regions (I36).",
    ),
    InvariantId.I33: InvariantClaim(
        guarantees="Child ids are derived from parents; a FAILED attempt does not close execution.",
        invalidates="A nonempty child without ancestors; colliding EventId schemes.",
        recovery_dependency="Rebuild ids from parents; never mint a new chain on replay.",
        concurrency_dependency="Two retries of one execution_id mint distinct AttemptIds.",
        authority_dependency="command_id originates in I30 authorize, not in the identity helper.",
    ),
    InvariantId.I31: InvariantClaim(
        guarantees="FINDING_CREATED requires COMMITTED settlement with nonempty wal_id.",
        invalidates="Self-attested authoritative=True; emit without wal_id.",
        recovery_dependency="Missing intent is never committed.",
        concurrency_dependency="One AttemptId has at most one COMMITTED settlement.",
        authority_dependency="HMAC receipt is the authority bit; EventBus is not.",
    ),
    InvariantId.I32: InvariantClaim(
        guarantees="Outbox-before-bus; bus failure does not un-commit WAL.",
        invalidates="Notify consumers of a finding that is not in the outbox.",
        recovery_dependency="Rebuild outbox from committed emitted_events; replay dispatch.",
        concurrency_dependency="DeliveryId is recorded only after a successful emit.",
        authority_dependency="EventBus and DeliveryLedger are caches, not L0.",
    ),
    InvariantId.I34: InvariantClaim(
        guarantees="Each FailureClass has exactly one recovery policy; must_not forbids drift.",
        invalidates="A call site that retries or rolls back a fail-closed class.",
        recovery_dependency="I35 consults this table; it does not invent actions.",
        concurrency_dependency="Bus failure racing commit cannot flip rollback=True.",
        authority_dependency="AUTHORITY_LOSS is fail-closed, not panic-compensate.",
    ),
    InvariantId.I35: InvariantClaim(
        guarantees="VERIFY_INVARIANTS fail-closes if a prerequisite or reverse assumption fails.",
        invalidates="READY while recovered tickets fail I30 or settlements fail I31/I28.",
        recovery_dependency="This node *is* the recovery protocol.",
        concurrency_dependency="One RecoveryManager per run_id; no dual reconstruct.",
        authority_dependency="Partition plane fail-closed; Frontier journal may STALE_CONTINUE.",
    ),
    InvariantId.I36: InvariantClaim(
        guarantees="One writer per partition; lease acquire and settle are colocated.",
        invalidates="Replica propose_and_commit; LWW merge of two leaders.",
        recovery_dependency="Heal by replaying leader WAL after I35 READY.",
        concurrency_dependency="Acquire in A concurrent with settle in B is refused.",
        authority_dependency="A region is placement, not an authority domain.",
    ),
    InvariantId.I37: InvariantClaim(
        guarantees="OWNED → FENCED → OWNED; nobody writes in the gap.",
        invalidates="Dual-home; resurrected I30-invalid tickets; stale revision consume.",
        recovery_dependency="Activate only after I35 READY on the pending home.",
        concurrency_dependency="Old home and pending home cannot both believe they are leader.",
        authority_dependency="Fence token + epoch + revision are the live writer identity.",
    ),
}


def node_for(inv: InvariantId | str) -> InvariantNode:
    return INVARIANT_GRAPH[InvariantId(inv)]


def prerequisites_of(inv: InvariantId | str) -> tuple[InvariantId, ...]:
    return node_for(inv).prerequisites


def dependents_of(inv: InvariantId | str) -> tuple[InvariantId, ...]:
    key = InvariantId(inv)
    return tuple(node.id for node in INVARIANT_GRAPH.values() if key in node.prerequisites)


def claim_for(inv: InvariantId | str) -> InvariantClaim:
    return INVARIANT_CLAIMS[InvariantId(inv)]


def edge_for(src: InvariantId | str, dst: InvariantId | str) -> InvariantEdge:
    src_id = InvariantId(src)
    dst_id = InvariantId(dst)
    for edge in INVARIANT_EDGES:
        if edge.src is src_id and edge.dst is dst_id:
            return edge
    raise ProofGraphError(
        f"{PROOF_GRAPH_ID}: no edge {src_id.value} → {dst_id.value}",
        invariant=dst_id.value,
    )


def edges_into(dst: InvariantId | str) -> tuple[InvariantEdge, ...]:
    key = InvariantId(dst)
    return tuple(edge for edge in INVARIANT_EDGES if edge.dst is key)


def edges_out_of(src: InvariantId | str) -> tuple[InvariantEdge, ...]:
    key = InvariantId(src)
    return tuple(edge for edge in INVARIANT_EDGES if edge.src is key)


def reverse_assumptions_of(dst: InvariantId | str) -> tuple[str, ...]:
    """What ``dst`` assumes about each upstream invariant."""
    return tuple(edge.reverse_assumption for edge in edges_into(dst))


def transitive_prerequisites(inv: InvariantId | str) -> frozenset[InvariantId]:
    seen: set[InvariantId] = set()
    stack = list(prerequisites_of(inv))
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        stack.extend(prerequisites_of(cur))
    return frozenset(seen)


def assert_requires(child: InvariantId | str, parent: InvariantId | str) -> None:
    """Fail closed if the graph does not declare ``child`` depends on ``parent``."""
    child_id = InvariantId(child)
    parent_id = InvariantId(parent)
    if parent_id not in transitive_prerequisites(child_id):
        raise ProofGraphError(
            f"{PROOF_GRAPH_ID}: {child_id.value} does not depend on {parent_id.value}",
            invariant=child_id.value,
        )


def assert_graph_sound() -> None:
    """DAG, complete catalog, every field filled, I35→I30/I31, I37→I30."""
    if set(INVARIANT_GRAPH) != set(InvariantId):
        missing = set(InvariantId) - set(INVARIANT_GRAPH)
        extra = set(INVARIANT_GRAPH) - set(InvariantId)
        raise ProofGraphError(
            f"{PROOF_GRAPH_ID}: catalog mismatch missing={sorted(m.value for m in missing)} "
            f"extra={sorted(e.value for e in extra)}"
        )
    visiting: set[InvariantId] = set()
    visited: set[InvariantId] = set()

    def _walk(node_id: InvariantId) -> None:
        if node_id in visited:
            return
        if node_id in visiting:
            raise ProofGraphError(f"{PROOF_GRAPH_ID}: cycle at {node_id.value}")
        visiting.add(node_id)
        for pred in prerequisites_of(node_id):
            if pred not in INVARIANT_GRAPH:
                raise ProofGraphError(
                    f"{PROOF_GRAPH_ID}: {node_id.value} lists unknown prerequisite {pred.value}"
                )
            _walk(pred)
        visiting.remove(node_id)
        visited.add(node_id)

    for inv in InvariantId:
        _walk(inv)
        node = node_for(inv)
        if not node.name or not node.protects or not node.transitions or not node.recovery_rule:
            raise ProofGraphError(f"{PROOF_GRAPH_ID}: {inv.value} is missing required fields")
        if (
            not node.crash_windows
            or not node.concurrency_windows
            or not node.tests
            or not node.module
        ):
            raise ProofGraphError(f"{PROOF_GRAPH_ID}: {inv.value} is missing windows/tests/module")
        for pred in node.prerequisites:
            if pred not in INVARIANT_GRAPH:
                raise ProofGraphError(
                    f"{PROOF_GRAPH_ID}: {inv.value} prerequisite {pred.value} is not a node"
                )

    assert_requires(InvariantId.I35, InvariantId.I30)
    assert_requires(InvariantId.I35, InvariantId.I31)
    assert_requires(InvariantId.I35, InvariantId.I32)
    assert_requires(InvariantId.I35, InvariantId.I33)
    assert_requires(InvariantId.I35, InvariantId.I28)
    assert_requires(InvariantId.I35, InvariantId.I22)
    assert_requires(InvariantId.I37, InvariantId.I30)
    assert_requires(InvariantId.I37, InvariantId.I36)
    assert_requires(InvariantId.I36, InvariantId.I35)

    if set(INVARIANT_CLAIMS) != set(InvariantId):
        raise ProofGraphError(f"{PROOF_GRAPH_ID}: claims catalog is incomplete")
    for inv, claim in INVARIANT_CLAIMS.items():
        if not (
            claim.guarantees
            and claim.invalidates
            and claim.recovery_dependency
            and claim.concurrency_dependency
            and claim.authority_dependency
        ):
            raise ProofGraphError(f"{PROOF_GRAPH_ID}: {inv.value} claim is missing fields")

    declared_edges: set[tuple[InvariantId, InvariantId]] = {
        (pred, inv) for inv in InvariantId for pred in prerequisites_of(inv)
    }
    catalog_edges: set[tuple[InvariantId, InvariantId]] = {
        (edge.src, edge.dst) for edge in INVARIANT_EDGES
    }
    if declared_edges != catalog_edges:
        missing_edges = declared_edges - catalog_edges
        extra_edges = catalog_edges - declared_edges
        raise ProofGraphError(
            f"{PROOF_GRAPH_ID}: edge catalog mismatch "
            f"missing={sorted(missing_edges)} extra={sorted(extra_edges)}"
        )
    for edge in INVARIANT_EDGES:
        if not edge.statement or not edge.reverse_assumption:
            raise ProofGraphError(
                f"{PROOF_GRAPH_ID}: edge {edge.src.value}→{edge.dst.value} lacks semantics"
            )


def proof_catalog() -> tuple[dict[str, Any], ...]:
    return tuple(INVARIANT_GRAPH[inv].to_dict() for inv in InvariantId)


def edge_catalog() -> tuple[dict[str, Any], ...]:
    return tuple(edge.to_dict() for edge in INVARIANT_EDGES)


def _identity_up_to(identity: Any) -> str:
    for name in reversed(CAUSAL_CHAIN):
        if str(getattr(identity, name, "") or "").strip():
            return name
    return "command_id"


def verify_upstream_assumptions(observed: Any) -> None:
    """Fail closed when a downstream invariant's reverse assumption is false.

    Catches "I31 is locally COMMITTED but its I28 reservation is not on the
    ledger" and "I33 command_id was not authorized by I30".
    Empty recovered sets are a no-op (nothing to assume).
    """
    tickets = tuple(getattr(observed, "recovered_tickets", ()) or ())
    settlements = tuple(getattr(observed, "recovered_settlements", ()) or ())
    identities = tuple(getattr(observed, "recovered_identities", ()) or ())
    reservation_ids = {
        str(item).strip()
        for item in (getattr(observed, "recovered_reservation_ids", ()) or ())
        if str(item or "").strip()
    }
    for ticket in tickets:
        rid = str(getattr(ticket, "budget_reservation_id", "") or "").strip()
        if rid:
            reservation_ids.add(rid)
    ticket_commands = {
        str(getattr(ticket, "command_id", "") or "").strip()
        for ticket in tickets
        if str(getattr(ticket, "command_id", "") or "").strip()
    }

    # I31 assumes I28: COMMITTED settlement reservation is on the ledger.
    if reservation_ids:
        for result in settlements:
            status = str(getattr(result, "status", "") or "")
            findings = getattr(result, "committed_findings", ()) or ()
            if status != "COMMITTED" and not findings:
                continue
            rid = str(getattr(result, "budget_reservation_id", "") or "").strip()
            if rid and rid not in reservation_ids:
                edge = edge_for(InvariantId.I28, InvariantId.I31)
                raise ProofGraphError(
                    f"{InvariantId.I31.value}: {edge.reverse_assumption} "
                    f"(reservation {rid!r} not on ledger)",
                    invariant=InvariantId.I28.value,
                )

    # I33 assumes I30: command_id was authorized.
    if ticket_commands:
        for identity in identities:
            cmd = str(getattr(identity, "command_id", "") or "").strip()
            if cmd and cmd not in ticket_commands:
                edge = edge_for(InvariantId.I30, InvariantId.I33)
                raise ProofGraphError(
                    f"{InvariantId.I33.value}: {edge.reverse_assumption} "
                    f"(command_id {cmd!r} was not authorized)",
                    invariant=InvariantId.I30.value,
                )

    # I32 assumes I31: bus cannot emit without COMMITTED wal (already gated
    # by bus_emitted_without_outbox). I35 assumes I32: same flag.


def verify_recovery_prerequisites(observed: Any) -> None:
    """I35 VERIFY_INVARIANTS: recovered artifacts must satisfy I30/I31/I32/I33.

    Empty recovered sets are a no-op (nothing to violate). A populated set
    that fails a prerequisite cannot READY.
    """
    assert_graph_sound()
    tickets = tuple(getattr(observed, "recovered_tickets", ()) or ())
    for ticket in tickets:
        try:
            assert_authorization_causality(ticket)
        except AuthorizationCausalityError as exc:
            raise ProofGraphError(
                f"{InvariantId.I35.value}: recovered ticket violates "
                f"{InvariantId.I30.value}: {exc}",
                invariant=InvariantId.I30.value,
            ) from exc
        live_revision = str(getattr(observed, "live_authority_revision", "") or "").strip()
        ticket_rev = str(getattr(ticket, "authority_revision", "") or "").strip()
        if live_revision and ticket_rev != live_revision:
            raise ProofGraphError(
                f"{InvariantId.I35.value}: recovered ticket revision {ticket_rev!r} "
                f"is not live {live_revision!r} ({InvariantId.I37.value})",
                invariant=InvariantId.I37.value,
            )

    settlements = tuple(getattr(observed, "recovered_settlements", ()) or ())
    for result in settlements:
        status = str(getattr(result, "status", "") or "")
        findings = getattr(result, "committed_findings", ()) or ()
        if status != "COMMITTED" and not findings:
            continue
        try:
            assert_settlement_causality(result)
        except SettlementCausalityError as exc:
            raise ProofGraphError(
                f"{InvariantId.I35.value}: recovered settlement violates "
                f"{InvariantId.I31.value}: {exc}",
                invariant=InvariantId.I31.value,
            ) from exc

    identities = tuple(getattr(observed, "recovered_identities", ()) or ())
    for identity in identities:
        try:
            assert_causal_identity_chain(identity, up_to=_identity_up_to(identity))
        except CausalIdentityError as exc:
            raise ProofGraphError(
                f"{InvariantId.I35.value}: recovered identity violates "
                f"{InvariantId.I33.value}: {exc}",
                invariant=InvariantId.I33.value,
            ) from exc

    if bool(getattr(observed, "bus_emitted_without_outbox", False)):
        raise ProofGraphError(
            f"{InvariantId.I35.value}: EventBus emit without durable outbox "
            f"violates {InvariantId.I32.value}",
            invariant=InvariantId.I32.value,
        )

    # I5 & I26: Budget conservation verification
    budget_state = getattr(observed, "recovered_budget_state", None) or getattr(
        observed, "budget_state", None
    )
    if budget_state is not None and isinstance(budget_state, dict):
        total = int(budget_state.get("total", 0))
        consumed = int(budget_state.get("consumed", 0))
        outstanding = int(budget_state.get("outstanding", 0))
        available = int(budget_state.get("available", 0))
        slab_reserved = int(budget_state.get("slab_reserved", 0))

        if total > 0 or consumed > 0 or outstanding > 0 or available > 0:
            if slab_reserved > 0:
                # I26 Multi-Raft Quota Slab Conservation
                expected_sum = consumed + outstanding + slab_reserved + available
                if expected_sum != total:
                    raise ProofGraphError(
                        f"{InvariantId.I35.value}: Recovered Multi-Raft budget state violates "
                        f"I26 slab conservation: consumed({consumed}) + "
                        f"outstanding({outstanding}) + slab_reserved({slab_reserved}) + "
                        f"available({available}) = {expected_sum} != total({total})",
                        invariant="I26",
                    )
            else:
                # I5 Single-Partition Budget Conservation
                expected_sum = consumed + outstanding + available
                if expected_sum != total:
                    raise ProofGraphError(
                        f"{InvariantId.I35.value}: Recovered budget state violates "
                        f"I5 conservation: consumed({consumed}) + "
                        f"outstanding({outstanding}) + available({available}) = "
                        f"{expected_sum} != total({total})",
                        invariant="I5",
                    )

    verify_upstream_assumptions(observed)


_TICKET_KEYS = (
    "tickets",
    "authorized_tickets",
    "execution_tickets",
    "recovered_tickets",
)
_SETTLEMENT_KEYS = ("settlements", "settlement_results", "recovered_settlements")
_IDENTITY_KEYS = ("identities", "causal_identities", "recovered_identities")


@dataclass(frozen=True, slots=True)
class RecoveredProofArtifacts:
    """Artifacts I35 VERIFY_INVARIANTS can check without inventing state."""

    tickets: tuple[Any, ...] = ()
    settlements: tuple[Any, ...] = ()
    identities: tuple[Any, ...] = ()
    bus_emitted_without_outbox: bool = False
    live_authority_revision: str = ""


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [item for item in value if item is not None]
    return [value]


def _from_keys(payload: Mapping[str, Any], keys: tuple[str, ...]) -> list[Any]:
    found: list[Any] = []
    for key in keys:
        if key in payload:
            found.extend(_as_list(payload.get(key)))
    return found


def _as_ticket(raw: Any) -> Any:
    if raw is None or not isinstance(raw, dict):
        return raw
    request = raw.get("request")
    token = None
    if isinstance(request, dict):
        token_raw = request.get("scope_token")
        token = SimpleNamespace(**token_raw) if isinstance(token_raw, dict) else token_raw
        request_ns = SimpleNamespace(scope_token=token)
    elif request is not None:
        request_ns = request
    else:
        request_ns = SimpleNamespace(scope_token=raw.get("scope_token"))
    return SimpleNamespace(
        scope_token_hash=str(raw.get("scope_token_hash") or ""),
        budget_reservation_id=str(raw.get("budget_reservation_id") or ""),
        authority_revision=str(raw.get("authority_revision") or ""),
        command_id=str(raw.get("command_id") or ""),
        request=request_ns,
    )


def _as_settlement(raw: Any) -> Any:
    if raw is None or not isinstance(raw, dict):
        return raw
    delta = raw.get("state_delta") if isinstance(raw.get("state_delta"), dict) else {}
    findings = (
        raw.get("committed_findings")
        or (delta or {}).get("reportable_findings")
        or (delta or {}).get("findings")
        or ()
    )
    wal_id = str(raw.get("wal_id") or raw.get("_wal_id") or "").strip()
    status = str(raw.get("status") or "").strip()
    if not status and (findings or raw.get("_is_settlement_intent")):
        # A settlement intent that carried findings must still satisfy I31.
        status = "COMMITTED" if findings else ""
    return SimpleNamespace(
        status=status,
        wal_id=wal_id,
        committed_findings=tuple(findings or ()),
        execution_id=str(raw.get("execution_id") or ""),
        command_id=str(raw.get("command_id") or ""),
        attempt_id=str(raw.get("attempt_id") or ""),
        settlement_id=str(raw.get("settlement_id") or ""),
        budget_reservation_id=str(raw.get("budget_reservation_id") or ""),
    )


def _as_identity(raw: Any) -> Any:
    if raw is None or not isinstance(raw, dict):
        return raw
    return SimpleNamespace(
        command_id=str(raw.get("command_id") or ""),
        execution_id=str(raw.get("execution_id") or ""),
        attempt_id=str(raw.get("attempt_id") or ""),
        settlement_id=str(raw.get("settlement_id") or ""),
        wal_id=str(raw.get("wal_id") or raw.get("_wal_id") or ""),
        event_id=str(raw.get("event_id") or ""),
        delivery_id=str(raw.get("delivery_id") or ""),
    )


def _iter_wal_records(wal: Any) -> list[Any]:
    if wal is None:
        return []
    records: list[Any] = []
    for attr in ("entries", "committed_entries", "_entries"):
        values = getattr(wal, attr, None)
        if values:
            records.extend(list(values))
            break
    if not records and hasattr(wal, "recover_deltas"):
        try:
            records.extend(list(wal.recover_deltas() or ()))
        except Exception:
            pass
    if not records and hasattr(wal, "since"):
        try:
            records.extend(list(wal.since(None) or ()))
        except Exception:
            pass
    return records


def collect_recovered_proof_artifacts(
    *,
    payload: Any = None,
    wal: Any = None,
) -> RecoveredProofArtifacts:
    """Pull I30/I31/I33 artifacts from a checkpoint payload and WAL. Never invent."""
    mapping: dict[str, Any] = dict(payload) if isinstance(payload, Mapping) else {}
    tickets = [_as_ticket(item) for item in _from_keys(mapping, _TICKET_KEYS)]
    for key in ("ticket", "authorized_ticket", "execution_ticket"):
        if mapping.get(key) is not None:
            tickets.append(_as_ticket(mapping.get(key)))
    settlements = [_as_settlement(item) for item in _from_keys(mapping, _SETTLEMENT_KEYS)]
    identities = [_as_identity(item) for item in _from_keys(mapping, _IDENTITY_KEYS)]
    for record in _iter_wal_records(wal):
        entry = record if isinstance(record, dict) else getattr(record, "__dict__", None)
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status") or "")
        if (
            entry.get("_is_settlement_intent")
            or "committed_findings" in entry
            or status in {"COMMITTED", "REJECTED", "DEDUPLICATED"}
        ):
            settlements.append(_as_settlement(entry))
        if entry.get("execution_id") and (
            entry.get("command_id") or entry.get("attempt_id") or entry.get("settlement_id")
        ):
            identities.append(_as_identity(entry))
        if entry.get("ticket_id") or (
            entry.get("scope_token_hash") and entry.get("command_id") is not None
        ):
            tickets.append(_as_ticket(entry))
    live = str(mapping.get("live_authority_revision") or mapping.get("authority_revision") or "")
    bus_gap = bool(mapping.get("bus_emitted_without_outbox"))
    return RecoveredProofArtifacts(
        tickets=tuple(item for item in tickets if item is not None),
        settlements=tuple(item for item in settlements if item is not None),
        identities=tuple(item for item in identities if item is not None),
        bus_emitted_without_outbox=bus_gap,
        live_authority_revision=live.strip(),
    )


def assert_transfer_does_not_resurrect(
    tickets: Iterable[Any],
    *,
    live_revision: str,
) -> None:
    """I37 cannot mint I30 authority.

    An I30-invalid ticket stays invalid across the fence. An I30-valid
    ticket bound to the *new* revision would mean transfer forged a ticket
    — refuse. I30-valid tickets with a stale revision are dead, as required.
    """
    assert_requires(InvariantId.I37, InvariantId.I30)
    live = str(live_revision or "").strip()
    for ticket in tickets:
        try:
            assert_authorization_causality(ticket)
        except AuthorizationCausalityError as exc:
            raise ProofGraphError(
                f"{InvariantId.I37.value}: cannot resurrect I30-invalid ticket: {exc}",
                invariant=InvariantId.I30.value,
            ) from exc
        ticket_rev = str(getattr(ticket, "authority_revision", "") or "").strip()
        if live and ticket_rev == live:
            raise ProofGraphError(
                f"{InvariantId.I37.value}: ticket already bound to post-activate "
                "revision; transfer cannot mint I30 authority",
                invariant=InvariantId.I30.value,
            )


__all__ = [
    "INVARIANT_CLAIMS",
    "INVARIANT_EDGES",
    "INVARIANT_GRAPH",
    "InvariantClaim",
    "InvariantEdge",
    "InvariantId",
    "InvariantNode",
    "PROOF_GRAPH_ID",
    "ProofGraphError",
    "RecoveredProofArtifacts",
    "assert_graph_sound",
    "assert_requires",
    "assert_transfer_does_not_resurrect",
    "claim_for",
    "collect_recovered_proof_artifacts",
    "dependents_of",
    "edge_catalog",
    "edge_for",
    "edges_into",
    "edges_out_of",
    "node_for",
    "prerequisites_of",
    "proof_catalog",
    "reverse_assumptions_of",
    "transitive_prerequisites",
    "verify_recovery_prerequisites",
    "verify_upstream_assumptions",
]
