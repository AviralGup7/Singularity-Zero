"""Password-derived AES-256-GCM envelope encryption using Argon2id."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

try:
    from argon2.low_level import Type, hash_secret_raw
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    Type: Any = None  # type: ignore[no-redef]
    hash_secret_raw: Any = None  # type: ignore[no-redef]
    hashes: Any = None  # type: ignore[no-redef]
    AESGCM: Any = None  # type: ignore[no-redef]
    HKDF: Any = None  # type: ignore[no-redef]
    CRYPTOGRAPHY_AVAILABLE = False

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

# Fallback stub for Cython acceleration
try:
    import cython_aesgcm  # type: ignore

    CYTHON_AVAILABLE = True
except ImportError:
    CYTHON_AVAILABLE = False

ARGON2ID_AESGCM_PREFIX = "csp-a256gcm-argon2id-v1:"


@dataclass(frozen=True)
class Argon2idParameters:
    """KDF parameters for passphrase-derived AES-256-GCM keys."""

    time_cost: int = 4
    memory_cost: int = 131072
    parallelism: int = 4
    salt_len: int = 16

    def to_dict(self) -> dict[str, int]:
        return {
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "salt_len": self.salt_len,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Argon2idParameters:
        return cls(
            time_cost=max(2, int(data.get("time_cost", 4))),
            memory_cost=max(65536, int(data.get("memory_cost", 131072))),
            parallelism=max(1, int(data.get("parallelism", 4))),
            salt_len=max(8, int(data.get("salt_len", 16))),
        )


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def secure_wipe(buffer: bytearray | memoryview | None) -> None:
    """Best-effort wipe for mutable plaintext buffers."""
    if buffer is None:
        return
    view = buffer if isinstance(buffer, memoryview) else memoryview(buffer)
    for idx in range(len(view)):
        view[idx] = 0


class SecretLease:
    """Context manager that keeps plaintext in a mutable buffer and wipes it on exit."""

    def __init__(self, plaintext: bytes) -> None:
        self._buffer = bytearray(plaintext)
        self._released = False

    @property
    def bytes(self) -> bytes:
        if self._released:
            raise RuntimeError("secret lease has been released")
        return bytes(self._buffer)

    @property
    def text(self) -> str:
        return self.bytes.decode("utf-8")

    def expose_bytearray(self) -> bytearray:
        """Return the mutable plaintext buffer for integrations that can avoid strings."""
        if self._released:
            raise RuntimeError("secret lease has been released")
        return self._buffer

    def wipe(self) -> None:
        secure_wipe(self._buffer)
        self._released = True

    def __enter__(self) -> SecretLease:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.wipe()


class Argon2idAESGCM:
    """Password-derived AES-256-GCM envelope encryption."""

    def __init__(self, passphrase: str | bytes, params: Argon2idParameters | None = None) -> None:
        if not passphrase:
            raise ValueError("passphrase must not be empty")
        self._passphrase = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
        self.params = params or Argon2idParameters()

    @staticmethod
    def derive_key(
        passphrase: str | bytes,
        salt: bytes,
        params: Argon2idParameters | None = None,
    ) -> bytes:
        if not passphrase:
            raise ValueError("passphrase must not be empty")
        raw = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
        kdf_params = params or Argon2idParameters()
        return hash_secret_raw(
            secret=raw,
            salt=salt,
            time_cost=kdf_params.time_cost,
            memory_cost=kdf_params.memory_cost,
            parallelism=kdf_params.parallelism,
            hash_len=32,
            type=Type.ID,
        )

    def encrypt(
        self, data: str | bytes, aad: bytes | None = None, info: bytes | None = None
    ) -> str:
        raw = data if isinstance(data, bytes) else data.encode("utf-8")
        salt = os.urandom(self.params.salt_len)
        nonce = os.urandom(12)
        key = self.derive_key(self._passphrase, salt, self.params)
        try:
            if info is not None:
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=info,
                )
                subkey = hkdf.derive(key)
                secure_wipe(bytearray(key))
                key = subkey

            if CYTHON_AVAILABLE:
                ciphertext = cython_aesgcm.encrypt(key, nonce, raw, aad)
            else:
                ciphertext = AESGCM(key).encrypt(nonce, raw, aad)
        finally:
            secure_wipe(bytearray(key))

        envelope = {
            "v": 1,
            "alg": "AES-256-GCM",
            "kdf": "argon2id",
            "params": self.params.to_dict(),
            "salt": _b64e(salt),
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ciphertext),
            "created_at": datetime.now(UTC).isoformat(),
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        return ARGON2ID_AESGCM_PREFIX + encoded

    def decrypt(
        self, encrypted: str | bytes, aad: bytes | None = None, info: bytes | None = None
    ) -> bytes:
        text = encrypted.decode("utf-8") if isinstance(encrypted, bytes) else encrypted
        if not text.startswith(ARGON2ID_AESGCM_PREFIX):
            raise ValueError("unsupported encryption envelope")
        payload = base64.urlsafe_b64decode(text[len(ARGON2ID_AESGCM_PREFIX) :].encode("ascii"))
        envelope = json.loads(payload.decode("utf-8"))
        params = Argon2idParameters.from_dict(cast(dict[str, Any], envelope["params"]))
        salt = _b64d(cast(str, envelope["salt"]))
        nonce = _b64d(cast(str, envelope["nonce"]))
        ciphertext = _b64d(cast(str, envelope["ciphertext"]))
        key = self.derive_key(self._passphrase, salt, params)
        try:
            if info is not None:
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=info,
                )
                subkey = hkdf.derive(key)
                secure_wipe(bytearray(key))
                key = subkey

            if CYTHON_AVAILABLE:
                return cast(bytes, cython_aesgcm.decrypt(key, nonce, ciphertext, aad))
            else:
                return cast(bytes, AESGCM(key).decrypt(nonce, ciphertext, aad))
        finally:
            secure_wipe(bytearray(key))

    def decrypt_lease(
        self, encrypted: str | bytes, aad: bytes | None = None, info: bytes | None = None
    ) -> SecretLease:
        plaintext = self.decrypt(encrypted, aad, info)
        try:
            return SecretLease(plaintext)
        finally:
            secure_wipe(bytearray(plaintext))
