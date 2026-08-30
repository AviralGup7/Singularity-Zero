"""I36 — multi-region consistency is not a second authority plane.

The topology diagram shows Region A and Region B each with
\"Authority + FrontierWAL\". That is a placement picture, not a license
for two writers. Global budgets, authority revisions, and leases already
assume a single writer per partition (I7 / I17 / I18). This module makes
the cross-region rules executable so a relay or replica cannot invent a
weaker model.

Live CLI remains single-node quorum-1. Region id defaults to ``local``.
Exotic multi-host failover is still out of scope; the outcome is named.

P0-1: ``activate_ownership`` across regions requires a live PartitionWAL
replicate path reporting caught_up. The Frontier journal relay alone is
non-authority and must not unlock activate.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

I36_REGION_CONSISTENCY = "I36"
DEFAULT_REGION_ID = "local"
GLOBAL_AUTHORITY_PARTITION = "P-0000"


class RegionRole(StrEnum):
    """What this process is allowed to do for one partition."""

    AUTHORITY_HOME = "authority_home"
    REPLICA = "replica"
    PARTITIONED = "partitioned"


class RegionDecision(StrEnum):
    ACCEPT = "accept"
    REFUSE = "refuse"
    FAIL_CLOSED = "fail_closed"
    JOURNAL_ONLY = "journal_only"


class RegionQuestion(StrEnum):
    REGION_IS_AUTHORITY_DOMAIN = "region_is_authority_domain"
    ONE_GLOBAL_AUTHORITY = "one_global_authority"
    INDEPENDENT_COMMAND_ACCEPT = "independent_command_accept"
    WAL_ORDERING = "wal_ordering"
    CONSISTENCY_MODEL = "consistency_model"
    NETWORK_PARTITION = "network_partition"
    BOTH_REGIONS_WRITABLE = "both_regions_writable"
    PARTITION_HEALING = "partition_healing"
    WHO_WINS = "who_wins"
    REVISION_CONFLICT = "revision_conflict"
    BUDGET_SPANS_REGIONS = "budget_spans_regions"
    LEASE_ACQUIRE_A_SETTLE_B = "lease_acquire_a_settle_b"
    EXECUTION_MAY_MIGRATE = "execution_may_migrate"
    MIGRATE_AFTER_ATTEMPT = "migrate_after_attempt"


@dataclass(frozen=True, slots=True)
class RegionContractRow:
    question: RegionQuestion
    answer: str
    decision: RegionDecision
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "question": self.question.value,
            "answer": self.answer,
            "decision": self.decision.value,
            "notes": self.notes,
        }


REGION_CONTRACT: dict[RegionQuestion, RegionContractRow] = {
    RegionQuestion.REGION_IS_AUTHORITY_DOMAIN: RegionContractRow(
        question=RegionQuestion.REGION_IS_AUTHORITY_DOMAIN,
        answer="No. A region is a placement / replica / latency boundary.",
        decision=RegionDecision.REFUSE,
        notes="Authority is P-0000 plus exactly one leader per partition (I7/I17).",
    ),
    RegionQuestion.ONE_GLOBAL_AUTHORITY: RegionContractRow(
        question=RegionQuestion.ONE_GLOBAL_AUTHORITY,
        answer="Yes. P-0000 is the only global writer for budget, placement, and policy watermark.",
        decision=RegionDecision.ACCEPT,
        notes="Partition leaders write only their own partition log.",
    ),
    RegionQuestion.INDEPENDENT_COMMAND_ACCEPT: RegionContractRow(
        question=RegionQuestion.INDEPENDENT_COMMAND_ACCEPT,
        answer="No. Only the region that currently hosts the partition leader may admit mutations.",
        decision=RegionDecision.REFUSE,
        notes="A replica may cache and relay. It must not propose_and_commit.",
    ),
    RegionQuestion.WAL_ORDERING: RegionContractRow(
        question=RegionQuestion.WAL_ORDERING,
        answer="Partition-ordered. There is no global total order across partitions.",
        decision=RegionDecision.ACCEPT,
        notes="P-0000 has its own log. FrontierWAL is a scan journal, not L0.",
    ),
    RegionQuestion.CONSISTENCY_MODEL: RegionContractRow(
        question=RegionQuestion.CONSISTENCY_MODEL,
        answer="Single-writer linearizability per partition. Followers are read replicas after Raft commit.",
        decision=RegionDecision.ACCEPT,
        notes="HLC / LWW apply only to the FrontierWAL CRDT scan journal (non-authority).",
    ),
    RegionQuestion.NETWORK_PARTITION: RegionContractRow(
        question=RegionQuestion.NETWORK_PARTITION,
        answer="Non-leader / minority region is fail-closed for mutations (I34 AUTHORITY_LOSS).",
        decision=RegionDecision.FAIL_CLOSED,
        notes="Do not panic-compensate leases on the disconnected side.",
    ),
    RegionQuestion.BOTH_REGIONS_WRITABLE: RegionContractRow(
        question=RegionQuestion.BOTH_REGIONS_WRITABLE,
        answer="No for the same partition. Different partitions may be homed in different regions.",
        decision=RegionDecision.REFUSE,
        notes="Live CLI is quorum-1 single-node; multi-home placement is specified, not clustered.",
    ),
    RegionQuestion.PARTITION_HEALING: RegionContractRow(
        question=RegionQuestion.PARTITION_HEALING,
        answer="Leader PartitionWAL is source of truth. Follower restores by sequential replay (I16/I35).",
        decision=RegionDecision.ACCEPT,
        notes="LWW must not merge two leaders. Divergent equal placement_version is fail-closed.",
    ),
    RegionQuestion.WHO_WINS: RegionContractRow(
        question=RegionQuestion.WHO_WINS,
        answer="The region that holds the leader at the current placement_version / ownership epoch.",
        decision=RegionDecision.ACCEPT,
        notes="Not last-write-wins. Not gossip lex-min/max.",
    ),
    RegionQuestion.REVISION_CONFLICT: RegionContractRow(
        question=RegionQuestion.REVISION_CONFLICT,
        answer="Higher placement_version / ownership epoch wins. Stale revision commands are rejected (I18).",
        decision=RegionDecision.REFUSE,
        notes="Equal version + disagreeing state hash is ReplicaDivergenceError, not a merge.",
    ),
    RegionQuestion.BUDGET_SPANS_REGIONS: RegionContractRow(
        question=RegionQuestion.BUDGET_SPANS_REGIONS,
        answer="No. Reservations live only on P-0000. Regions do not hold a local budget copy.",
        decision=RegionDecision.REFUSE,
        notes="A worker in another region may request; only P-0000 mutates Available/Outstanding.",
    ),
    RegionQuestion.LEASE_ACQUIRE_A_SETTLE_B: RegionContractRow(
        question=RegionQuestion.LEASE_ACQUIRE_A_SETTLE_B,
        answer="No, unless B has become the same partition leader via fenced P-0000 migration.",
        decision=RegionDecision.REFUSE,
        notes="A foreign-region settle of a live lease is not a settlement. It is a split brain.",
    ),
    RegionQuestion.EXECUTION_MAY_MIGRATE: RegionContractRow(
        question=RegionQuestion.EXECUTION_MAY_MIGRATE,
        answer="Yes, only through P-0000 5-stage fenced transfer (Axiom 7), and only when no attempt is in flight.",
        decision=RegionDecision.ACCEPT,
        notes="Ghost/actor move without a placement epoch is not authority migration.",
    ),
    RegionQuestion.MIGRATE_AFTER_ATTEMPT: RegionContractRow(
        question=RegionQuestion.MIGRATE_AFTER_ATTEMPT,
        answer="No. An in-flight AttemptId is bound to the current partition (I33).",
        decision=RegionDecision.REFUSE,
        notes="Retry after FAILED may run after a completed fenced transfer. ACTIVE/RESERVED attempts may not move.",
    ),
}


class RegionConsistencyError(PermissionError):
    """A cross-region action would create a second authority (I36)."""


def contract_row(question: RegionQuestion | str) -> RegionContractRow:
    return REGION_CONTRACT[RegionQuestion(question)]


def region_catalog() -> tuple[dict[str, Any], ...]:
    return tuple(REGION_CONTRACT[q].to_dict() for q in RegionQuestion)


def _norm(value: str | None) -> str:
    return str(value or "").strip() or DEFAULT_REGION_ID


def assert_region_may_accept_command(
    *,
    local_region: str,
    leader_region: str,
    role: RegionRole | str = RegionRole.AUTHORITY_HOME,
    partition_id: str = "",
) -> None:
    """Only the current leader home may admit a mutating command."""
    role_key = RegionRole(role)
    if role_key is RegionRole.PARTITIONED:
        raise RegionConsistencyError(
            f"{I36_REGION_CONSISTENCY}: region {local_region!r} is partitioned; "
            f"refuse mutations on {partition_id or 'partition'}"
        )
    if role_key is RegionRole.REPLICA:
        raise RegionConsistencyError(
            f"{I36_REGION_CONSISTENCY}: replica {local_region!r} cannot accept "
            f"commands for {partition_id or 'partition'}"
        )
    if _norm(local_region) != _norm(leader_region):
        raise RegionConsistencyError(
            f"{I36_REGION_CONSISTENCY}: only leader home {leader_region!r} may "
            f"accept commands (local={local_region!r} partition={partition_id or '-'})"
        )


def assert_budget_home(*, local_region: str, p0000_region: str) -> None:
    """Budget mutations are not regional copies."""
    if _norm(local_region) != _norm(p0000_region):
        raise RegionConsistencyError(
            f"{I36_REGION_CONSISTENCY}: budget reservations cannot span regions "
            f"(local={local_region!r} P-0000 home={p0000_region!r})"
        )


def assert_lease_settle_colocated(*, acquire_region: str, settle_region: str) -> None:
    """A lease reserved in A cannot be settled in B without a fenced move."""
    if _norm(acquire_region) != _norm(settle_region):
        raise RegionConsistencyError(
            f"{I36_REGION_CONSISTENCY}: lease acquired in {acquire_region!r} "
            f"cannot be settled in {settle_region!r}"
        )


def assert_migration_allowed(*, attempt_in_flight: bool, attempt_terminal: bool = False) -> None:
    """In-flight attempts do not migrate. Terminal attempts may be transferred."""
    if attempt_in_flight and not attempt_terminal:
        raise RegionConsistencyError(
            f"{I36_REGION_CONSISTENCY}: migration forbidden after an attempt starts (I33)"
        )


def resolve_authority_revision(
    *,
    local_placement_version: int,
    remote_placement_version: int,
    local_state_hash: str = "",
    remote_state_hash: str = "",
) -> str:
    """Return which side is authoritative after healing. Never LWW-merge."""
    local_v = int(local_placement_version)
    remote_v = int(remote_placement_version)
    if remote_v > local_v:
        return "remote"
    if local_v > remote_v:
        return "local"
    local_hash = str(local_state_hash or "").strip()
    remote_hash = str(remote_state_hash or "").strip()
    if local_hash and remote_hash and local_hash != remote_hash:
        raise RegionConsistencyError(
            f"{I36_REGION_CONSISTENCY}: equal placement_version {local_v} with "
            "divergent state hashes; fail-closed (I11/I16), do not LWW-merge"
        )
    return "equal"


def classify_peer_entry(entry: Any) -> RegionDecision:
    """Peer WAL rows that look like settlement / commands are not locally authoritative."""
    if not isinstance(entry, dict):
        return RegionDecision.JOURNAL_ONLY
    if entry.get("_is_settlement_intent") or "state_delta" in entry:
        return RegionDecision.REFUSE
    if entry.get("command_type") or entry.get("command_id"):
        return RegionDecision.REFUSE
    if str(entry.get("authoritative") or "").strip().lower() in {"1", "true", "yes"}:
        return RegionDecision.REFUSE
    return RegionDecision.JOURNAL_ONLY


def refuse_replica_authority_commit(*, reason: str = "peer_wal_reconcile") -> None:
    """Call sites that used to apply peer settlements as local authority."""
    raise RegionConsistencyError(
        f"{I36_REGION_CONSISTENCY}: replica must not commit peer authority ({reason})"
    )


@dataclass(frozen=True, slots=True)
class ObservedRegionState:
    local_region: str = DEFAULT_REGION_ID
    leader_region: str = DEFAULT_REGION_ID
    p0000_region: str = DEFAULT_REGION_ID
    role: RegionRole = RegionRole.AUTHORITY_HOME
    partition_id: str = GLOBAL_AUTHORITY_PARTITION
    acquire_region: str = DEFAULT_REGION_ID
    settle_region: str = DEFAULT_REGION_ID
    attempt_in_flight: bool = False
    attempt_terminal: bool = False
    local_placement_version: int = 1
    remote_placement_version: int = 1
    local_state_hash: str = ""
    remote_state_hash: str = ""
    network_partitioned: bool = False


@dataclass(frozen=True, slots=True)
class RegionVerdict:
    may_accept_commands: bool
    may_settle_lease: bool
    may_reserve_budget: bool
    may_migrate: bool
    heal_winner: str
    role: RegionRole
    notes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "may_accept_commands": self.may_accept_commands,
            "may_settle_lease": self.may_settle_lease,
            "may_reserve_budget": self.may_reserve_budget,
            "may_migrate": self.may_migrate,
            "heal_winner": self.heal_winner,
            "role": self.role.value,
            "notes": list(self.notes),
        }


def evaluate_region_policy(observed: ObservedRegionState) -> RegionVerdict:
    """Fold the contract into one verdict for a concrete observation."""
    notes: list[str] = []
    role = RegionRole.PARTITIONED if observed.network_partitioned else RegionRole(observed.role)

    may_accept = False
    try:
        assert_region_may_accept_command(
            local_region=observed.local_region,
            leader_region=observed.leader_region,
            role=role,
            partition_id=observed.partition_id,
        )
        may_accept = True
    except RegionConsistencyError as exc:
        notes.append(str(exc))

    may_budget = False
    try:
        assert_budget_home(local_region=observed.local_region, p0000_region=observed.p0000_region)
        may_budget = True
    except RegionConsistencyError as exc:
        notes.append(str(exc))

    may_settle = False
    try:
        assert_lease_settle_colocated(
            acquire_region=observed.acquire_region,
            settle_region=observed.settle_region,
        )
        may_settle = True
    except RegionConsistencyError as exc:
        notes.append(str(exc))

    may_migrate = False
    try:
        assert_migration_allowed(
            attempt_in_flight=observed.attempt_in_flight,
            attempt_terminal=observed.attempt_terminal,
        )
        may_migrate = True
    except RegionConsistencyError as exc:
        notes.append(str(exc))

    try:
        winner = resolve_authority_revision(
            local_placement_version=observed.local_placement_version,
            remote_placement_version=observed.remote_placement_version,
            local_state_hash=observed.local_state_hash,
            remote_state_hash=observed.remote_state_hash,
        )
    except RegionConsistencyError as exc:
        winner = "fail_closed"
        notes.append(str(exc))

    return RegionVerdict(
        may_accept_commands=may_accept,
        may_settle_lease=may_settle,
        may_reserve_budget=may_budget,
        may_migrate=may_migrate,
        heal_winner=winner,
        role=role,
        notes=tuple(notes),
    )


__all__ = [
    "DEFAULT_REGION_ID",
    "GLOBAL_AUTHORITY_PARTITION",
    "I36_REGION_CONSISTENCY",
    "ObservedRegionState",
    "REGION_CONTRACT",
    "RegionConsistencyError",
    "RegionContractRow",
    "RegionDecision",
    "RegionQuestion",
    "RegionRole",
    "RegionVerdict",
    "assert_budget_home",
    "assert_lease_settle_colocated",
    "assert_migration_allowed",
    "assert_region_may_accept_command",
    "classify_peer_entry",
    "contract_row",
    "evaluate_region_policy",
    "refuse_replica_authority_commit",
    "region_catalog",
    "resolve_authority_revision",
]
