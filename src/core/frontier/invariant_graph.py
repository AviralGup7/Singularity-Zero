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

Every node names prerequisites, the state it protects, the transitions it
constrains, crash / concurrency windows, the recovery rule, and the tests
that prove it. Runtime gates consult the graph: I35 VERIFY_INVARIANTS
fail-closes on a prerequisite violation; I37 activate refuses to resurrect
an I30-invalid ticket.
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
        return {
            "id": self.id.value,
            "name": self.name,
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


def node_for(inv: InvariantId | str) -> InvariantNode:
    return INVARIANT_GRAPH[InvariantId(inv)]


def prerequisites_of(inv: InvariantId | str) -> tuple[InvariantId, ...]:
    return node_for(inv).prerequisites


def dependents_of(inv: InvariantId | str) -> tuple[InvariantId, ...]:
    key = InvariantId(inv)
    return tuple(node.id for node in INVARIANT_GRAPH.values() if key in node.prerequisites)


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


def proof_catalog() -> tuple[dict[str, Any], ...]:
    return tuple(INVARIANT_GRAPH[inv].to_dict() for inv in InvariantId)


def _identity_up_to(identity: Any) -> str:
    for name in reversed(CAUSAL_CHAIN):
        if str(getattr(identity, name, "") or "").strip():
            return name
    return "command_id"


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
    "INVARIANT_GRAPH",
    "InvariantId",
    "InvariantNode",
    "PROOF_GRAPH_ID",
    "ProofGraphError",
    "RecoveredProofArtifacts",
    "assert_graph_sound",
    "assert_requires",
    "assert_transfer_does_not_resurrect",
    "collect_recovered_proof_artifacts",
    "dependents_of",
    "node_for",
    "prerequisites_of",
    "proof_catalog",
    "transitive_prerequisites",
    "verify_recovery_prerequisites",
]
