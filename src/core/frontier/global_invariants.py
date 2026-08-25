"""Cross-subsystem invariants (I30–I32).

Local invariants (budget math, lease CAS, Raft CRC) live next to their
aggregates. These checks bind *across* authorization, settlement, and
notification so a ticket or EventBus payload cannot exist without
authoritative provenance.
"""

from __future__ import annotations

from typing import Any

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
    "I30_AUTHORIZATION_CAUSALITY",
    "I31_SETTLEMENT_CAUSALITY",
    "I32_EVENTBUS_NON_AUTHORITY",
    "SettlementCausalityError",
    "assert_authorization_causality",
    "assert_settlement_causality",
    "event_bus_is_not_authority",
]
