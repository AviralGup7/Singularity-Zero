"""Cross-subsystem invariants (I30–I36).

Local invariants (budget math, lease CAS, Raft CRC) live next to their
aggregates. These checks bind *across* authorization, settlement, and
notification so a ticket or EventBus payload cannot exist without
authoritative provenance.
"""

from __future__ import annotations

from typing import Any

from src.core.frontier.causal_identity import (
    CAUSAL_CHAIN,
    I33_CAUSAL_IDENTITY_CHAIN,
    CausalIdentity,
    CausalIdentityError,
    assert_causal_identity_chain,
    mint_causal_identity,
)
from src.core.frontier.failure_model import I34_FAILURE_RECOVERY
from src.core.frontier.recovery_protocol import I35_RECOVERY_PROTOCOL
from src.core.frontier.region_model import I36_REGION_CONSISTENCY

I30_AUTHORIZATION_CAUSALITY = "I30"
I31_SETTLEMENT_CAUSALITY = "I31"
I32_EVENTBUS_NON_AUTHORITY = "I32"


class AuthorizationCausalityError(PermissionError):
    """Ticket is missing a required causal binding (I30)."""


class SettlementCausalityError(PermissionError):
    """Attempted to publish a finding that is not durably committed (I31)."""


def assert_authorization_causality(ticket: Any) -> None:
    """I30: a ticket exists only if scope, reservation, revision, and command bind.

    ``AuthorizedExecutionTicket`` MUST reference all four:
    ScopeToken hash, BudgetReservation id, AuthorityRevision, CommandId.
    """
    required = (
        ("scope_token_hash", getattr(ticket, "scope_token_hash", "")),
        ("budget_reservation_id", getattr(ticket, "budget_reservation_id", "")),
        ("authority_revision", getattr(ticket, "authority_revision", "")),
        ("command_id", getattr(ticket, "command_id", "")),
    )
    missing = [name for name, value in required if not str(value or "").strip()]
    if missing:
        raise AuthorizationCausalityError(
            f"{I30_AUTHORIZATION_CAUSALITY}: ticket missing causal bindings: {', '.join(missing)}"
        )
    request = getattr(ticket, "request", None)
    token = getattr(request, "scope_token", None) if request is not None else None
    if token is None:
        raise AuthorizationCausalityError(
            f"{I30_AUTHORIZATION_CAUSALITY}: ticket has no ScopeToken on the bound request"
        )


def assert_settlement_causality(result: Any) -> None:
    """I31: no consumer-visible finding unless settlement is COMMITTED with a wal_id."""
    status = str(getattr(result, "status", "") or "")
    wal_id = str(getattr(result, "wal_id", "") or "")
    if status != "COMMITTED" or not wal_id:
        raise SettlementCausalityError(
            f"{I31_SETTLEMENT_CAUSALITY}: FINDING_CREATED requires COMMITTED settlement "
            f"with durable wal_id (status={status!r} wal_id={wal_id!r})"
        )


def event_bus_is_not_authority() -> str:
    """I32: EventBus is an in-process dispatcher; outbox / WAL remain authority."""
    return I32_EVENTBUS_NON_AUTHORITY


__all__ = [
    "AuthorizationCausalityError",
    "CAUSAL_CHAIN",
    "CausalIdentity",
    "CausalIdentityError",
    "I30_AUTHORIZATION_CAUSALITY",
    "I31_SETTLEMENT_CAUSALITY",
    "I32_EVENTBUS_NON_AUTHORITY",
    "I33_CAUSAL_IDENTITY_CHAIN",
    "I34_FAILURE_RECOVERY",
    "I35_RECOVERY_PROTOCOL",
    "I36_REGION_CONSISTENCY",
    "SettlementCausalityError",
    "assert_authorization_causality",
    "assert_causal_identity_chain",
    "assert_settlement_causality",
    "event_bus_is_not_authority",
    "mint_causal_identity",
]
