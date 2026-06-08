"""
RESEARCH PROTOTYPE — not wired into the active scan pipeline. See docs/architecture.md Implementation Status table for current state.

P2P Gossip Protocol with BFT and Noise Encryption Simulation.

Byzantine-fault-tolerant message validation uses Ed25519 signatures, not
symmetric MACs. The previous SHA-256-of-(payload+key) construction was a MAC,
not a signature: any peer that knew the "public" key could forge valid
"signatures" for any other peer. This was a critical authenticity gap.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

logger = logging.getLogger(__name__)


class NoiseChannel:
    """Simulates a Noise-protocol encrypted channel using ChaCha20Poly1305."""

    def __init__(self, shared_key: bytes | None = None) -> None:
        self.key = shared_key or ChaCha20Poly1305.generate_key()
        self.cipher = ChaCha20Poly1305(self.key)

    def encrypt_payload(self, data: dict[str, Any]) -> bytes:
        nonce = os.urandom(12)
        payload = json.dumps(data, sort_keys=True).encode("utf-8")
        ciphertext = self.cipher.encrypt(nonce, payload, None)
        return nonce + ciphertext

    def decrypt_payload(self, encrypted_data: bytes) -> dict[str, Any]:
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        plaintext = self.cipher.decrypt(nonce, ciphertext, None)
        return cast(dict[str, Any], json.loads(plaintext.decode("utf-8")))


def _canonical_payload(state_dict: dict[str, Any]) -> bytes:
    return json.dumps(state_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _serialize_public_key(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def _deserialize_public_key(public_key_hex: str) -> Ed25519PublicKey:
    raw = bytes.fromhex(public_key_hex)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


class BFTMessageValidator:
    """Byzantine Fault Tolerant message validation using Ed25519 signatures.

    The private key is held only by the signing agent; the public key is
    distributed to peers. Verification is unforgeable.
    """

    @staticmethod
    def generate_keypair() -> tuple[Ed25519PrivateKey, str]:
        """Return ``(private_key, public_key_hex)`` for a new identity."""
        private = Ed25519PrivateKey.generate()
        return private, _serialize_public_key(private.public_key())

    @staticmethod
    def sign_state(state_dict: dict[str, Any], private_key: Ed25519PrivateKey | str) -> str:
        """Sign a state payload. Accepts either an ``Ed25519PrivateKey`` (preferred)
        or, for backward compatibility, a hex-encoded raw private key string.
        """
        if isinstance(private_key, str):
            raw = bytes.fromhex(private_key)
            if len(raw) != 32:
                raise ValueError("Ed25519 private key must be 32 bytes")
            private_key = Ed25519PrivateKey.from_private_bytes(raw)
        payload = _canonical_payload(state_dict)
        signature = private_key.sign(payload)
        return signature.hex()

    @staticmethod
    def verify_state(state_dict: dict[str, Any], signature: str, public_key: str) -> bool:
        """Verify a signature using the peer's Ed25519 public key (hex)."""
        try:
            pubkey = _deserialize_public_key(public_key)
            payload = _canonical_payload(state_dict)
            pubkey.verify(bytes.fromhex(signature), payload)
            return True
        except (InvalidSignature, ValueError, TypeError) as exc:
            logger.debug("BFT signature verification failed: %s", exc)
            return False
