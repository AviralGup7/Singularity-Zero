"""HMAC-SHA256 command-receipt signing (I13).

Receipts bind command identity, partition, Raft term/index, and state hashes.
The previous SHA-256-of-payload digest is not a signature and is rejected by
``verify_receipt_signature``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Mapping
from typing import Any

from src.core.contracts.canonical_target import canonical_state_encode

DEFAULT_KEY_ID = "authority-hmac-v1"
_ephemeral_material: bytes | None = None


def signing_key_id() -> str:
    """Return the active signer key id (never the hardcoded K-2026-A placeholder)."""
    raw = os.environ.get("AUTHORITY_SIGNING_KEY_ID", "").strip()
    return raw or DEFAULT_KEY_ID


def _signing_key() -> bytes:
    """HMAC key. Never a well-known fallback string.

    Prefer AUTHORITY_SIGNING_KEY, then APP_SECRET_KEY. If neither is set,
    mint a process-local random key so in-process verify still works and
    the old published default cannot forge receipts.
    """
    global _ephemeral_material
    material = os.environ.get("AUTHORITY_SIGNING_KEY", "").encode("utf-8")
    if not material:
        material = os.environ.get("APP_SECRET_KEY", "").encode("utf-8")
    if not material:
        if _ephemeral_material is None:
            import secrets

            _ephemeral_material = secrets.token_bytes(32)
        material = _ephemeral_material
    return hashlib.sha256(material).digest()


def receipt_bind_payload(
    *,
    command_id: str,
    partition_id: str,
    raft_term: int,
    raft_index: int,
    entry_hash: str,
    previous_state_hash: str,
    state_hash_at_commit: str,
    signer_key_id: str,
) -> dict[str, Any]:
    """Canonical fields bound into the receipt MAC."""
    return {
        "command_id": str(command_id),
        "partition_id": str(partition_id),
        "raft_term": int(raft_term),
        "raft_index": int(raft_index),
        "entry_hash": str(entry_hash),
        "previous_state_hash": str(previous_state_hash),
        "state_hash_at_commit": str(state_hash_at_commit),
        "signer_key_id": str(signer_key_id),
    }


def sign_receipt(payload: Mapping[str, Any]) -> str:
    """HMAC-SHA256 over the canonical receipt payload. Returns hex digest."""
    raw = canonical_state_encode("v2.1.0", dict(payload))
    return hmac.new(_signing_key(), raw, hashlib.sha256).hexdigest()


def verify_receipt_signature(payload: Mapping[str, Any], signature: str) -> bool:
    """Constant-time verification of a receipt MAC."""
    if not signature:
        return False
    expected = sign_receipt(payload)
    return hmac.compare_digest(expected, str(signature))
