"""HMAC-SHA256 command-receipt signing and multi-generation key rotation protocol (I13).

Receipts bind command identity, partition, Raft term/index, and state hashes.
Supports:
- Multi-generation key registry with key_generation monotonic counter
- Two-key overlap window during rolling authority rotation
- Cryptographic verification against specific generation or fallback overlap
- Dynamic Raft-committed key rotation protocol
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from src.core.contracts.canonical_target import canonical_state_encode

DEFAULT_KEY_ID = "authority-hmac-v1"
_ephemeral_material: bytes | None = None


class PersistentSigningKeyRequired(RuntimeError):
    """HMAC receipts cannot verify across restart without an env key."""


def domain_separated_key(material: bytes, *, purpose: str) -> bytes:
    """HKDF-SHA256 Expand from a master secret with a purpose label (B19).

    Receipt HMAC, mesh AEAD, and JWT must not share raw key bytes.
    """
    salt = b"singularity-zero-hkdf-v1"
    prk = hmac.new(salt, material, hashlib.sha256).digest()
    info = f"cstp/{purpose}".encode()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def signing_key_from_env() -> bool:
    return bool(
        os.environ.get("AUTHORITY_SIGNING_KEY", "").strip()
        or os.environ.get("APP_SECRET_KEY", "").strip()
    )


def require_persistent_signing_key(*, force: bool = False) -> None:
    """Fail-closed in production/staging when no persistent HMAC key is set.

    Local/dev keeps the process-local random fallback so unit tests work.
    """
    env = os.environ.get("APP_ENV", "").strip().lower()
    if not force and env not in {"production", "prod", "staging"}:
        return
    if signing_key_from_env():
        return
    raise PersistentSigningKeyRequired(
        "AUTHORITY_SIGNING_KEY or APP_SECRET_KEY required so HMAC receipts "
        "and I30 tickets verify across process restart"
    )


@dataclass(frozen=True, slots=True)
class KeyGenerationRecord:
    key_id: str
    generation: int
    raw_material: bytes
    created_at_unix: float


class AuthorityKeyRing:
    """Manages multi-generation authority signing keys with an active key and overlap window."""

    def __init__(self) -> None:
        self._keys: dict[str, KeyGenerationRecord] = {}  # key_id -> record
        self._active_key_id: str = ""
        self._active_generation: int = 1
        self._lock = threading.RLock()
        self._bootstrap_default_key()

    def _bootstrap_default_key(self) -> None:
        raw_key = os.environ.get("AUTHORITY_SIGNING_KEY", "").encode("utf-8")
        if not raw_key:
            raw_key = os.environ.get("APP_SECRET_KEY", "").encode("utf-8")
        if not raw_key:
            global _ephemeral_material
            if _ephemeral_material is None:
                import secrets

                _ephemeral_material = secrets.token_bytes(32)
            raw_key = _ephemeral_material

        key_id = os.environ.get("AUTHORITY_SIGNING_KEY_ID", "").strip() or DEFAULT_KEY_ID
        digest = hashlib.sha256(raw_key).digest()

        rec = KeyGenerationRecord(
            key_id=key_id,
            generation=1,
            raw_material=digest,
            created_at_unix=0.0,
        )
        self._keys[key_id] = rec
        self._active_key_id = key_id
        self._active_generation = 1

    @property
    def active_key_id(self) -> str:
        with self._lock:
            return self._active_key_id

    @property
    def active_generation(self) -> int:
        with self._lock:
            return self._active_generation

    def active_material(self) -> bytes:
        """Raw bytes for the active generation (HKDF input for domain keys)."""
        with self._lock:
            rec = self._keys.get(self._active_key_id)
            if rec is None:
                raise RuntimeError("AuthorityKeyRing has no active key")
            return rec.raw_material

    def get_key_material(self, key_id: str | None = None) -> bytes:
        with self._lock:
            target_id = key_id or self._active_key_id
            rec = self._keys.get(target_id)
            if rec is not None:
                return rec.raw_material
            if self._active_key_id in self._keys:
                return self._keys[self._active_key_id].raw_material
            return hashlib.sha256(b"fallback").digest()

    def rotate_key(self, new_key_id: str, new_material: bytes) -> KeyGenerationRecord:
        """Rotate to a new key generation while preserving prior generation for overlap verification."""
        with self._lock:
            next_gen = self._active_generation + 1
            digest = hashlib.sha256(new_material).digest()
            rec = KeyGenerationRecord(
                key_id=new_key_id,
                generation=next_gen,
                raw_material=digest,
                created_at_unix=0.0,
            )
            self._keys[new_key_id] = rec
            self._active_key_id = new_key_id
            self._active_generation = next_gen
            return rec


GLOBAL_KEY_RING = AuthorityKeyRing()


def signing_key_id() -> str:
    """Return the active signer key id."""
    return GLOBAL_KEY_RING.active_key_id


def active_key_generation() -> int:
    """Return the active monotonic key generation counter."""
    return GLOBAL_KEY_RING.active_generation


def _signing_key(key_id: str | None = None) -> bytes:
    """Return the HMAC key for the active key or specific key ID."""
    return GLOBAL_KEY_RING.get_key_material(key_id)


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
    key_generation: int = 1,
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
        "key_generation": int(key_generation),
    }


def sign_receipt(payload: Mapping[str, Any], key_id: str | None = None) -> str:
    """HMAC-SHA256 over the canonical receipt payload. Returns hex digest."""
    raw = canonical_state_encode("v2.1.0", dict(payload))
    target_key_id = key_id or str(payload.get("signer_key_id", ""))
    return hmac.new(_signing_key(target_key_id), raw, hashlib.sha256).hexdigest()


def verify_receipt_signature(payload: Mapping[str, Any], signature: str) -> bool:
    """Constant-time verification of a receipt MAC across active key and rotation overlap window."""
    if not signature:
        return False
    # 1. Try with signer_key_id declared in payload
    signer_id = str(payload.get("signer_key_id", ""))
    expected = sign_receipt(payload, key_id=signer_id)
    if hmac.compare_digest(expected, str(signature)):
        return True

    # 2. Try with active key in key ring (overlap fallback)
    active_expected = sign_receipt(payload, key_id=GLOBAL_KEY_RING.active_key_id)
    return hmac.compare_digest(active_expected, str(signature))


def mesh_secret_key(master: bytes | None = None) -> bytes:
    """Derive 32-byte MESH_SECRET material (AES-256-GCM) from the authority master."""
    material = master if master is not None else GLOBAL_KEY_RING.active_material()
    return domain_separated_key(material, purpose="mesh-aes-256-gcm")


def jwt_session_key(master: bytes | None = None) -> bytes:
    """Derive JWT session signing key bytes from the authority master."""
    material = master if master is not None else GLOBAL_KEY_RING.active_material()
    return domain_separated_key(material, purpose="jwt-session")


def apply_rotate_authority_key_command(payload: dict) -> KeyGenerationRecord:
    """Apply RotateAuthorityKeyCommand payload to GLOBAL_KEY_RING."""
    import base64
    import secrets

    new_key_id = str(payload.get("new_key_id") or "").strip()
    if not new_key_id:
        new_key_id = f"authority-hmac-v{GLOBAL_KEY_RING.active_generation + 1}"
    raw_b64 = str(payload.get("key_material_b64") or "").strip()
    if raw_b64:
        material = base64.b64decode(raw_b64)
    else:
        material = secrets.token_bytes(32)
    return GLOBAL_KEY_RING.rotate_key(new_key_id, material)
