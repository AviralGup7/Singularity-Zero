"""HMAC settlement receipt for FINDING_CREATED (I31).

``authoritative`` is not a flag the emitter may set on itself. A finding
event is authoritative only when it carries COMMITTED + wal_id + an HMAC
receipt that ``verify_finding_receipt`` accepts. EventBus refuses anything
else; dispatch_committed_findings is the only producer that stamps this.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from src.core.frontier.receipt_crypto import sign_receipt, verify_receipt_signature

_RECEIPT_FIELDS = ("wal_id", "settlement_id", "command_id", "status")


def receipt_bind_fields(
    *,
    wal_id: str,
    settlement_id: str = "",
    command_id: str = "",
    status: str = "COMMITTED",
) -> dict[str, str]:
    return {
        "wal_id": str(wal_id or "").strip(),
        "settlement_id": str(settlement_id or "").strip(),
        "command_id": str(command_id or "").strip(),
        "status": str(status or "").strip() or "COMMITTED",
    }


def stamp_finding_receipt(
    *,
    wal_id: str,
    settlement_id: str = "",
    command_id: str = "",
    status: str = "COMMITTED",
) -> dict[str, Any]:
    """Fields stamped onto FINDING_CREATED by dispatch_committed_findings."""
    bound = receipt_bind_fields(
        wal_id=wal_id,
        settlement_id=settlement_id,
        command_id=command_id,
        status=status,
    )
    return {
        **bound,
        "settlement_status": bound["status"],
        "receipt_hmac": sign_receipt(bound),
    }


def verify_finding_receipt(payload: Mapping[str, Any] | None) -> bool:
    """True only for a COMMITTED settlement receipt with a valid HMAC."""
    data = payload or {}
    wal_id = str(data.get("wal_id") or "").strip()
    status = str(data.get("settlement_status") or data.get("status") or "").strip()
    signature = str(data.get("receipt_hmac") or "").strip()
    if not wal_id or status != "COMMITTED" or not signature:
        return False
    bound = receipt_bind_fields(
        wal_id=wal_id,
        settlement_id=str(data.get("settlement_id") or ""),
        command_id=str(data.get("command_id") or ""),
        status=status,
    )
    return verify_receipt_signature(bound, signature)


__all__ = [
    "receipt_bind_fields",
    "stamp_finding_receipt",
    "verify_finding_receipt",
]
