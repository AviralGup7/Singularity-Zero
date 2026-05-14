"""
Cyber Security Test Pipeline - Encrypted Local Vault
Implements AES-256-GCM secure storage for target credentials.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CyberVault:
    """
    Hardware-secured (local) vault for sensitive target secrets.
    Uses PBKDF2 for key derivation and AES-GCM for authenticated encryption.
    """
    def __init__(self, master_key: str, salt: bytes | None = None) -> None:
        # Fix #216: Reject empty master_key — empty password produces a weak but valid key.
        if not master_key:
            raise ValueError("master_key must not be empty; provide a strong passphrase.")
        self._salt = salt or os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=600000, # Increased to 600k per Audit #143 (OWASP 2024 guidance)
        )
        key = kdf.derive(master_key.encode())
        self._aesgcm = AESGCM(key)

    def encrypt(self, data: str) -> str:
        """Encrypt data and return base64 string: salt|nonce|ciphertext."""
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, data.encode(), None)
        # Bundle salt, nonce, and ciphertext
        payload = self._salt + nonce + ciphertext
        return base64.b64encode(payload).decode()

    def decrypt(self, encrypted_payload: str) -> str:
        """Decrypt base64 payload."""
        payload = base64.b64decode(encrypted_payload)
        salt = payload[:16]
        nonce = payload[16:28]
        ciphertext = payload[28:]

        # Verify salt matches (if reusing vault instance)
        if salt != self._salt:
             # Fix Audit #8: Raise ValueError on salt mismatch
             raise ValueError("Salt mismatch — cannot decrypt with this vault instance. "
                            "Decryption requires a vault initialized with the original salt.")

        decrypted = self._aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode()

class TargetSecretStore:
    """Manager for target-specific secrets."""
    def __init__(self, vault: CyberVault) -> None:
        self._vault = vault
        self._secrets: dict[str, str] = {}

    def set_secret(self, target: str, key: str, value: str) -> None:
        secret_id = f"{target}:{key}"
        self._secrets[secret_id] = self._vault.encrypt(value)

    def get_secret(self, target: str, key: str) -> str | None:
        secret_id = f"{target}:{key}"
        encrypted = self._secrets.get(secret_id)
        if not encrypted:
            return None
        return self._vault.decrypt(encrypted)

    def to_dict(self) -> dict[str, str]:
        return self._secrets

    @classmethod
    def from_dict(cls, vault: CyberVault, data: dict[str, str]) -> TargetSecretStore:
        store = cls(vault)
        store._secrets = data
        return store
