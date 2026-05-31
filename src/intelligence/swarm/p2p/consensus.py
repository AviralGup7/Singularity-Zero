"""
P2P Gossip Protocol with BFT and Noise Encryption Simulation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

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
        return json.loads(plaintext.decode("utf-8"))


class BFTMessageValidator:
    """Byzantine Fault Tolerant message validation."""

    @staticmethod
    def sign_state(state_dict: dict[str, Any], private_key: str) -> str:
        # Simplistic signature for prototype
        payload = json.dumps(state_dict, sort_keys=True)
        return hashlib.sha256(f"{payload}{private_key}".encode()).hexdigest()

    @staticmethod
    def verify_state(state_dict: dict[str, Any], signature: str, public_key: str) -> bool:
        # In a real PKI, we'd use ECDSA or Ed25519. We simulate with a symmetric key for the prototype
        expected = hashlib.sha256(
            f"{json.dumps(state_dict, sort_keys=True)}{public_key}".encode()
        ).hexdigest()
        return expected == signature
