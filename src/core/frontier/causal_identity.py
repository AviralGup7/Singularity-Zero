"""I33 — complete causal identity chain.

Replay, retries, deduplication, and crash recovery are proveable only when
every layer of work has a stable parent-linked identity:

    CommandId → ExecutionId → AttemptId → SettlementId → WalId → EventId → DeliveryId

Child ids are derived from their parent (SHA-256 truncated). A non-empty
child is illegal unless every ancestor is also non-empty.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from typing import Any

I33_CAUSAL_IDENTITY_CHAIN = "I33"

CAUSAL_CHAIN: tuple[str, ...] = (
    "command_id",
    "execution_id",
    "attempt_id",
    "settlement_id",
    "wal_id",
    "event_id",
    "delivery_id",
)

_PARENT: dict[str, str] = {
    "execution_id": "command_id",
    "attempt_id": "execution_id",
    "settlement_id": "attempt_id",
    "wal_id": "settlement_id",
    "event_id": "wal_id",
    "delivery_id": "event_id",
}


class CausalIdentityError(PermissionError):
    """A causal identity is missing a parent binding (I33)."""


def _digest(*parts: object) -> str:
    raw = ":".join(str(p) for p in parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def derive_command_id(execution_id: str) -> str:
    """Fallback command identity when no authorizing command exists yet."""
    return f"cmd_{_digest('command', execution_id)}"


def derive_attempt_id(execution_id: str, attempt_n: int = 1) -> str:
    n = max(1, int(attempt_n or 1))
    return f"att_{_digest('attempt', execution_id, n)}"


def derive_settlement_id(attempt_id: str) -> str:
    return f"stl_{_digest('settlement', attempt_id)}"


def derive_event_id_from_wal(wal_id: str, sequence: int = 0) -> str:
    """Durable event identity: same wal_id + seq always yields the same event_id."""
    return f"evt_{_digest('event', wal_id, int(sequence))}"


def derive_delivery_id(event_id: str, delivery_n: int = 1) -> str:
    n = max(1, int(delivery_n or 1))
    return f"dlv_{_digest('delivery', event_id, n)}"


def attempt_n_from_output(stage_output: Any, default: int = 1) -> int:
    """Map StageOutput.retry_count / retry_metrics onto a 1-based attempt number."""
    n = max(1, int(default or 1))
    retry_count = int(getattr(stage_output, "retry_count", 0) or 0)
    n = max(n, retry_count + 1)
    metrics = getattr(stage_output, "metrics", None)
    if isinstance(metrics, dict):
        n = max(n, int(metrics.get("retry_count") or 0) + 1)
        rm = metrics.get("retry_metrics")
        if isinstance(rm, dict):
            attempts = int(rm.get("attempts") or 0)
            if attempts > 0:
                n = max(n, attempts)
    return n


def command_id_from_ctx(ctx: Any, execution_id: str) -> str:
    """Prefer an authorizing command on ctx/ticket; otherwise derive from execution."""
    for obj in (ctx, getattr(ctx, "result", None)):
        if obj is None:
            continue
        direct = str(getattr(obj, "command_id", "") or "").strip()
        if direct:
            return direct
        for attr in ("ticket", "authorized_ticket", "execution_ticket"):
            ticket = getattr(obj, attr, None)
            if ticket is None:
                continue
            bound = str(getattr(ticket, "command_id", "") or "").strip()
            if bound:
                return bound
    return derive_command_id(execution_id)


@dataclass(frozen=True, slots=True)
class CausalIdentity:
    """Immutable parent-linked identity of one unit of work through the pipeline."""

    command_id: str
    execution_id: str
    attempt_id: str
    settlement_id: str
    wal_id: str = ""
    event_id: str = ""
    delivery_id: str = ""
    attempt_n: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "execution_id": self.execution_id,
            "attempt_id": self.attempt_id,
            "settlement_id": self.settlement_id,
            "wal_id": self.wal_id,
            "event_id": self.event_id,
            "delivery_id": self.delivery_id,
            "attempt_n": self.attempt_n,
        }

    def with_wal(self, wal_id: str) -> CausalIdentity:
        return replace(self, wal_id=str(wal_id or ""))

    def with_event(self, event_id: str) -> CausalIdentity:
        return replace(self, event_id=str(event_id or ""))

    def with_delivery(self, delivery_id: str) -> CausalIdentity:
        return replace(self, delivery_id=str(delivery_id or ""))

    def payload_fields(self) -> dict[str, Any]:
        """Fields stamped onto EventBus / outbox payloads for consumer dedup.

        Does not self-certify ``authoritative``. I31 authority is the HMAC
        settlement receipt stamped by ``dispatch_committed_findings``.
        """
        return self.to_dict()


def mint_causal_identity(
    *,
    execution_id: str,
    command_id: str = "",
    attempt_n: int = 1,
    attempt_id: str = "",
    settlement_id: str = "",
    wal_id: str = "",
    event_id: str = "",
    delivery_id: str = "",
) -> CausalIdentity:
    """Build a complete chain down to settlement (wal/event/delivery optional)."""
    exec_id = str(execution_id or "").strip()
    if not exec_id:
        raise CausalIdentityError(f"{I33_CAUSAL_IDENTITY_CHAIN}: execution_id is required")
    n = max(1, int(attempt_n or 1))
    cmd = str(command_id or "").strip() or derive_command_id(exec_id)
    attempt_id = str(attempt_id or "").strip() or derive_attempt_id(exec_id, n)
    stl = str(settlement_id or "").strip() or derive_settlement_id(attempt_id)
    identity = CausalIdentity(
        command_id=cmd,
        execution_id=exec_id,
        attempt_id=attempt_id,
        settlement_id=stl,
        wal_id=str(wal_id or ""),
        event_id=str(event_id or ""),
        delivery_id=str(delivery_id or ""),
        attempt_n=n,
    )
    up_to = (
        "delivery_id"
        if identity.delivery_id
        else (
            "event_id" if identity.event_id else ("wal_id" if identity.wal_id else "settlement_id")
        )
    )
    assert_causal_identity_chain(identity, up_to=up_to)
    return identity


def assert_causal_identity_chain(
    identity: Any,
    *,
    up_to: str = "settlement_id",
) -> None:
    """I33: a non-empty child requires every ancestor in CAUSAL_CHAIN to be set.

    ``up_to`` is the last required field (inclusive). Later fields may be empty
    until WAL commit / outbox / delivery.
    """
    if up_to not in CAUSAL_CHAIN:
        raise CausalIdentityError(f"{I33_CAUSAL_IDENTITY_CHAIN}: unknown chain field {up_to!r}")
    required = CAUSAL_CHAIN[: CAUSAL_CHAIN.index(up_to) + 1]
    values = {name: str(getattr(identity, name, "") or "").strip() for name in CAUSAL_CHAIN}
    missing = [name for name in required if not values[name]]
    if missing:
        raise CausalIdentityError(
            f"{I33_CAUSAL_IDENTITY_CHAIN}: missing causal bindings: {', '.join(missing)}"
        )
    for child, parent in _PARENT.items():
        if values[child] and not values[parent]:
            raise CausalIdentityError(
                f"{I33_CAUSAL_IDENTITY_CHAIN}: {child} requires parent {parent}"
            )


def identity_from_mapping(mapping: Any) -> CausalIdentity | None:
    """Rehydrate a chain from a WAL / outbox record. Returns None if incomplete."""
    if mapping is None:
        return None
    getter = mapping.get if isinstance(mapping, dict) else lambda k, d="": getattr(mapping, k, d)
    exec_id = str(getter("execution_id", "") or "").strip()
    if not exec_id:
        return None
    try:
        return mint_causal_identity(
            execution_id=exec_id,
            command_id=str(getter("command_id", "") or ""),
            attempt_n=int(getter("attempt_n", 1) or 1),
            attempt_id=str(getter("attempt_id", "") or ""),
            settlement_id=str(getter("settlement_id", "") or ""),
            wal_id=str(getter("wal_id", "") or getter("_wal_id", "") or ""),
            event_id=str(getter("event_id", "") or ""),
            delivery_id=str(getter("delivery_id", "") or ""),
        )
    except (CausalIdentityError, TypeError, ValueError):
        return None


__all__ = [
    "CAUSAL_CHAIN",
    "CausalIdentity",
    "CausalIdentityError",
    "I33_CAUSAL_IDENTITY_CHAIN",
    "assert_causal_identity_chain",
    "attempt_n_from_output",
    "command_id_from_ctx",
    "derive_attempt_id",
    "derive_command_id",
    "derive_delivery_id",
    "derive_event_id_from_wal",
    "derive_settlement_id",
    "identity_from_mapping",
    "mint_causal_identity",
]
