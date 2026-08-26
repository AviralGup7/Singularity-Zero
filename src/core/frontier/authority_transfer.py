"""I37 — authority transfer is a fence, not a dual-writer handoff.

I36 says who may write. This module says how home may move without a
window where A and B both believe they are leader.

    OWNED (A writes) → FENCED (nobody writes) → OWNED (B writes)

There is never a dual-writer interval. There is a fail-closed interval
(I34 AUTHORITY_LOSS). Stale AuthorityEpoch / FenceToken / AuthorityRevision
mutations are rejected. Tickets minted under the old revision cannot be
consumed after activate (I30).

Live CLI is still single-node quorum-1. The fence is enforced even then
so a later multi-home placement cannot invent a weaker transfer.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

I37_AUTHORITY_TRANSFER = "I37"


class TransferPhase(StrEnum):
    OWNED = "owned"
    FENCED = "fenced"


class AuthorityFenceError(PermissionError):
    """Mutation rejected because the authority epoch / fence is stale or sealed."""


@dataclass(frozen=True, slots=True)
class AuthorityLease:
    """The live writer identity for one partition (I37)."""

    partition_id: str
    home_region: str
    authority_epoch: int
    authority_revision: str
    fence_token: str
    leader_term: int
    phase: TransferPhase = TransferPhase.OWNED
    pending_home: str = ""
    pending_partition: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "partition_id": self.partition_id,
            "home_region": self.home_region,
            "authority_epoch": self.authority_epoch,
            "authority_revision": self.authority_revision,
            "fence_token": self.fence_token,
            "leader_term": self.leader_term,
            "phase": self.phase.value,
            "pending_home": self.pending_home,
            "pending_partition": self.pending_partition,
        }


@dataclass(frozen=True, slots=True)
class TransferRecord:
    """In-flight P-0000 transfer. Exists only while phase is FENCED."""

    aggregate_id: str
    from_partition: str
    to_partition: str
    to_region: str
    epoch: int
    fence_token: str
    revision: str
    leader_term: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "aggregate_id": self.aggregate_id,
            "from_partition": self.from_partition,
            "to_partition": self.to_partition,
            "to_region": self.to_region,
            "epoch": self.epoch,
            "fence_token": self.fence_token,
            "revision": self.revision,
            "leader_term": self.leader_term,
        }


def mint_fence_token(partition_id: str, epoch: int) -> str:
    raw = f"{partition_id}:{int(epoch)}:{uuid.uuid4().hex}".encode()
    return f"fnc_{hashlib.sha256(raw).hexdigest()[:20]}"


def derive_authority_revision(*, epoch: int, placement_version: int, fence_token: str) -> str:
    token = str(fence_token or "genesis")
    return f"arev_{int(epoch)}.{int(placement_version)}.{token[-8:]}"


def genesis_lease(
    partition_id: str, home_region: str, *, placement_version: int = 1
) -> AuthorityLease:
    return AuthorityLease(
        partition_id=str(partition_id),
        home_region=str(home_region or "local") or "local",
        authority_epoch=1,
        authority_revision=derive_authority_revision(
            epoch=1, placement_version=int(placement_version), fence_token=""
        ),
        fence_token="",
        leader_term=1,
        phase=TransferPhase.OWNED,
    )


def assert_mutation_allowed(
    lease: AuthorityLease,
    *,
    observed_region: str,
    observed_epoch: int,
    observed_token: str = "",
    observed_revision: str = "",
    observed_term: int | None = None,
) -> None:
    """Reject a mutation unless it carries the live fence (I37)."""
    if lease.phase is TransferPhase.FENCED:
        raise AuthorityFenceError(
            f"{I37_AUTHORITY_TRANSFER}: partition {lease.partition_id} is FENCED; "
            "no writer until activate (fail-closed, not dual-home)"
        )
    home = str(lease.home_region or "").strip()
    local = str(observed_region or "").strip() or home
    if home and local != home:
        raise AuthorityFenceError(
            f"{I37_AUTHORITY_TRANSFER}: home is {home!r}, local {local!r} cannot mutate "
            f"{lease.partition_id}"
        )
    if int(observed_epoch) != int(lease.authority_epoch):
        raise AuthorityFenceError(
            f"{I37_AUTHORITY_TRANSFER}: stale authority epoch "
            f"{observed_epoch} != live {lease.authority_epoch}"
        )
    live_token = str(lease.fence_token or "")
    seen_token = str(observed_token or "")
    if live_token and seen_token != live_token:
        raise AuthorityFenceError(
            f"{I37_AUTHORITY_TRANSFER}: stale fence token on {lease.partition_id}"
        )
    if observed_revision and str(observed_revision) != str(lease.authority_revision):
        raise AuthorityFenceError(
            f"{I37_AUTHORITY_TRANSFER}: stale authority revision "
            f"{observed_revision!r} != {lease.authority_revision!r}"
        )
    if observed_term is not None and int(observed_term) != int(lease.leader_term):
        raise AuthorityFenceError(
            f"{I37_AUTHORITY_TRANSFER}: stale leader term "
            f"{observed_term} != live {lease.leader_term}"
        )


def assert_ticket_revision_live(ticket_revision: str, live_revision: str) -> None:
    """I30 tickets die when the transfer activates a new revision."""
    ticket = str(ticket_revision or "").strip()
    live = str(live_revision or "").strip()
    if not ticket or not live or ticket != live:
        raise AuthorityFenceError(
            f"{I37_AUTHORITY_TRANSFER}: ticket revision {ticket!r} is not live {live!r}"
        )


def assert_tickets_not_resurrected(tickets: Any, *, live_revision: str) -> None:
    """I37 cannot mint I30 authority. Invalid tickets stay invalid across the fence."""
    from src.core.frontier.invariant_graph import (
        ProofGraphError,
        assert_transfer_does_not_resurrect,
    )

    try:
        assert_transfer_does_not_resurrect(tickets or (), live_revision=live_revision)
    except ProofGraphError as exc:
        raise AuthorityFenceError(str(exc)) from exc


def fence_lease(
    lease: AuthorityLease,
    *,
    pending_home: str,
    pending_partition: str,
    placement_version: int,
) -> tuple[AuthorityLease, str]:
    """OWNED → FENCED. Returns (fenced lease, new token). Home does not move."""
    if lease.phase is TransferPhase.FENCED:
        raise AuthorityFenceError(
            f"{I37_AUTHORITY_TRANSFER}: {lease.partition_id} is already FENCED"
        )
    epoch = int(lease.authority_epoch) + 1
    token = mint_fence_token(lease.partition_id, epoch)
    term = int(lease.leader_term) + 1
    fenced = replace(
        lease,
        authority_epoch=epoch,
        fence_token=token,
        leader_term=term,
        phase=TransferPhase.FENCED,
        pending_home=str(pending_home or lease.home_region),
        pending_partition=str(pending_partition or lease.partition_id),
        authority_revision=derive_authority_revision(
            epoch=epoch, placement_version=int(placement_version), fence_token=token
        ),
    )
    return fenced, token


def abort_lease(lease: AuthorityLease, *, placement_version: int) -> AuthorityLease:
    """FENCED → OWNED on original home (abort / timeout). Epoch bumps to kill in-flight tokens."""
    if lease.phase is not TransferPhase.FENCED:
        raise AuthorityFenceError(
            f"{I37_AUTHORITY_TRANSFER}: abort requires FENCED, not {lease.phase.value}"
        )
    epoch = int(lease.authority_epoch) + 1
    new_token = mint_fence_token(lease.partition_id, epoch)
    return replace(
        lease,
        phase=TransferPhase.OWNED,
        authority_epoch=epoch,
        fence_token=new_token,
        pending_home="",
        pending_partition="",
        authority_revision=derive_authority_revision(
            epoch=epoch,
            placement_version=int(placement_version),
            fence_token=new_token,
        ),
    )


def activate_lease(lease: AuthorityLease, *, placement_version: int) -> AuthorityLease:
    """FENCED → OWNED on pending home. Old token is dead (new revision)."""
    if lease.phase is not TransferPhase.FENCED:
        raise AuthorityFenceError(
            f"{I37_AUTHORITY_TRANSFER}: activate requires FENCED, not {lease.phase.value}"
        )
    dest = str(lease.pending_home or lease.home_region)
    dest_part = str(lease.pending_partition or lease.partition_id)
    return replace(
        lease,
        partition_id=dest_part,
        home_region=dest,
        phase=TransferPhase.OWNED,
        pending_home="",
        pending_partition="",
        authority_revision=derive_authority_revision(
            epoch=lease.authority_epoch,
            placement_version=int(placement_version),
            fence_token=lease.fence_token,
        ),
    )


__all__ = [
    "AuthorityFenceError",
    "AuthorityLease",
    "I37_AUTHORITY_TRANSFER",
    "TransferPhase",
    "TransferRecord",
    "abort_lease",
    "activate_lease",
    "assert_mutation_allowed",
    "assert_ticket_revision_live",
    "assert_tickets_not_resurrected",
    "derive_authority_revision",
    "fence_lease",
    "genesis_lease",
    "mint_fence_token",
]
