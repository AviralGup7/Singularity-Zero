"""
Cyber Security Test Pipeline - hardened credential vault.

Secrets are stored as Argon2id-derived AES-256-GCM envelopes. Access and
rotation events are emitted into the tamper-evident audit chain used by the
dashboard chain-of-custody viewer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Protocol, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.logging.audit import AuditEventType, get_audit_logger
from src.infrastructure.security.encryption import (
    Argon2idAESGCM,
    Argon2idParameters,
    SecretLease,
    sealed_bundle_decrypt,
    sealed_bundle_encrypt,
    secure_wipe,
)

logger = logging.getLogger(__name__)


class _AuditSink(Protocol):
    def log(self, *args: Any, **kwargs: Any) -> Any: ...


class VaultRotationPolicy:
    """Time-based key rotation policy for vault records."""

    def __init__(self, interval_seconds: float = 14400) -> None:
        self.interval_seconds = interval_seconds

    def is_due(self, rotated_at: float) -> bool:
        return (time.time() - rotated_at) >= self.interval_seconds


class CyberVault:
    """Passphrase-backed vault using a KEK/DEK envelope key hierarchy."""

    def __init__(
        self,
        master_key: str,
        salt: bytes | None = None,
        *,
        audit_logger: _AuditSink | None = None,
        rotation_policy: VaultRotationPolicy | None = None,
        kdf_params: Argon2idParameters | None = None,
        principal: str = "system",
    ) -> None:
        if not master_key:
            raise ValueError("master_key must not be empty; provide a strong passphrase.")
        self._master_key = master_key
        self._legacy_salt = salt
        self._audit_logger = audit_logger
        self._rotation_policy = rotation_policy or VaultRotationPolicy()
        self._kdf_params = kdf_params or Argon2idParameters()
        self._principal = principal
        self._key_version = 1
        self._created_at = time.time()
        self._rotated_at = self._created_at

        # KEK/DEK Hierarchy Initialization
        # Generate the master KEK using Argon2id derived from the master passphrase
        self._master_salt = salt or os.urandom(self._kdf_params.salt_len)
        self._kek = Argon2idAESGCM.derive_key(self._master_key, self._master_salt, self._kdf_params)

        # Generate a random Data Encrypting Key (DEK)
        self._dek = os.urandom(32)

        # Encrypt the DEK with the KEK
        aesgcm_kek = AESGCM(self._kek)
        self._dek_nonce = os.urandom(12)
        self._wrapped_dek = aesgcm_kek.encrypt(self._dek_nonce, self._dek, b"dek-envelope")

    @property
    def key_version(self) -> int:
        return self._key_version

    def _envelope(self) -> Argon2idAESGCM:
        # Compatibility envelope backing
        return Argon2idAESGCM(self._master_key, self._kdf_params)

    def _aad(self, purpose: str, key_version: int | None = None) -> bytes:
        payload: dict[str, object] = {
            "purpose": purpose,
        }
        if key_version is not None:
            payload["key_version"] = key_version
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _audit(self, action: str, result: str = "success", **details: Any) -> None:
        redacted = {k: v for k, v in details.items() if not k.endswith("_plaintext")}
        redacted.setdefault("vault_key_version", self._key_version)
        if self._audit_logger is not None:
            try:
                self._audit_logger.log(
                    event=f"credential.{action}",
                    user_id=self._principal,
                    resource_id=redacted.get("secret_id"),
                    details=redacted,
                )
                return
            except TypeError as exc:
                logger.warning("Operation failed in vault.py: %s", exc, exc_info=True)  # noqa: BLE001
        try:
            get_audit_logger().log(
                AuditEventType.SECURITY_EVENT,
                "local",
                self._principal,
                f"credential.{action}",
                result,
                redacted,
            )
        except (AttributeError, ValueError, OSError) as e:
            logger.warning("Vault: Audit logging failed: %s", e)

    def rotate_key(self, encrypted_records: dict[str, str] | None = None) -> dict[str, str]:
        """Advance the vault key version, generate a new DEK, and re-encrypt records."""
        records = encrypted_records or {}
        rotated: dict[str, str] = {}

        # Performance #5: Pre-derive KEK outside of record loop
        new_master_salt = os.urandom(self._kdf_params.salt_len)
        new_kek = Argon2idAESGCM.derive_key(self._master_key, new_master_salt, self._kdf_params)

        # Generate a new DEK
        new_dek = os.urandom(32)

        # Encrypt the new DEK with the new KEK
        aesgcm_new_kek = AESGCM(new_kek)
        new_dek_nonce = os.urandom(12)
        new_wrapped_dek = aesgcm_new_kek.encrypt(new_dek_nonce, new_dek, b"dek-envelope")

        # Decrypt records using the old DEK and re-encrypt with the new DEK
        next_version = self._key_version + 1
        for secret_id, encrypted in records.items():
            try:
                with self.decrypt_lease(encrypted, purpose=secret_id) as lease:
                    # Encrypt with new DEK
                    nonce = os.urandom(12)
                    ciphertext = AESGCM(new_dek).encrypt(
                        nonce, lease.bytes, self._aad(secret_id, next_version)
                    )
                    envelope = {
                        "v": next_version,
                        "alg": "AES-256-GCM-DEK",
                        "kek_salt": base64.b64encode(new_master_salt).decode("utf-8"),
                        "dek_nonce": base64.b64encode(new_dek_nonce).decode("utf-8"),
                        "wrapped_dek": base64.b64encode(new_wrapped_dek).decode("utf-8"),
                        "nonce": base64.b64encode(nonce).decode("utf-8"),
                        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
                    }
                    rotated[secret_id] = "csp-a256gcm-argon2id-v1:" + json.dumps(envelope)
            except Exception as e:
                logger.error("Vault: Failed to rotate secret %s: %s", secret_id, e)
                # Keep old record if rotation fails
                rotated[secret_id] = encrypted

        # Wipe old keys
        if hasattr(self, "_kek"):
            secure_wipe(bytearray(self._kek))
        if hasattr(self, "_dek"):
            secure_wipe(bytearray(self._dek))

        # Swap keys
        self._master_salt = new_master_salt
        self._kek = new_kek
        self._dek = new_dek
        self._dek_nonce = new_dek_nonce
        self._wrapped_dek = new_wrapped_dek

        self._key_version = next_version
        self._rotated_at = time.time()
        self._audit("rotate", secret_count=len(records))
        return rotated

    def rotate_if_due(
        self, encrypted_records: dict[str, str] | None = None
    ) -> dict[str, str] | None:
        if self._rotation_policy.is_due(self._rotated_at):
            return self.rotate_key(encrypted_records)
        return None

    def encrypt(
        self, data: str | bytes, *, purpose: str = "secret", key_version: int | None = None
    ) -> str:
        """Encrypt plaintext using standard KEK/DEK envelope encryption."""
        version = key_version or self._key_version
        raw_bytes = data if isinstance(data, bytes) else data.encode("utf-8")
        raw = bytearray(raw_bytes)
        try:
            # Generate KEK salt and derive KEK
            kek_salt = os.urandom(self._kdf_params.salt_len)
            kek = Argon2idAESGCM.derive_key(self._master_key, kek_salt, self._kdf_params)

            # Generate random DEK
            dek = os.urandom(32)

            # Wrap DEK using KEK
            dek_nonce = os.urandom(12)
            wrapped_dek = AESGCM(kek).encrypt(dek_nonce, dek, b"dek-envelope")

            # Encrypt data using DEK
            nonce = os.urandom(12)
            ciphertext = AESGCM(dek).encrypt(nonce, bytes(raw), self._aad(purpose, version))

            envelope = {
                "v": version,
                "alg": "AES-256-GCM-DEK",
                "kek_salt": base64.b64encode(kek_salt).decode("utf-8"),
                "dek_nonce": base64.b64encode(dek_nonce).decode("utf-8"),
                "wrapped_dek": base64.b64encode(wrapped_dek).decode("utf-8"),
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            }

            # Secure wipe
            secure_wipe(bytearray(kek))
            secure_wipe(bytearray(dek))

            self._audit("store", secret_id=purpose, key_version=version)
            return "csp-a256gcm-argon2id-v1:" + json.dumps(envelope)
        finally:
            secure_wipe(raw)

    def decrypt_lease(self, encrypted_payload: str, *, purpose: str = "secret") -> SecretLease:
        """Decrypt standard KEK/DEK envelope into a secret lease."""
        self._audit("access", secret_id=purpose)
        try:
            payload = encrypted_payload
            if payload.startswith("csp-a256gcm-argon2id-v1:"):
                payload = payload[len("csp-a256gcm-argon2id-v1:") :]
            try:
                envelope = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid encryption envelope: malformed JSON") from exc
            if envelope.get("alg") == "AES-256-GCM-DEK":
                kek_salt = base64.b64decode(envelope["kek_salt"])
                dek_nonce = base64.b64decode(envelope["dek_nonce"])
                wrapped_dek = base64.b64decode(envelope["wrapped_dek"])
                nonce = base64.b64decode(envelope["nonce"])
                ciphertext = base64.b64decode(envelope["ciphertext"])
                version = envelope.get("v", self._key_version)

                # Derive KEK
                kek = Argon2idAESGCM.derive_key(self._master_key, kek_salt, self._kdf_params)

                # Unwrap DEK
                dek = AESGCM(kek).decrypt(dek_nonce, wrapped_dek, b"dek-envelope")

                # Decrypt secret data
                plaintext = AESGCM(dek).decrypt(nonce, ciphertext, self._aad(purpose, version))

                # Secure wipe
                secure_wipe(bytearray(kek))
                secure_wipe(bytearray(dek))

                return SecretLease(plaintext)
        except (
            json.JSONDecodeError,
            KeyError,
            ValueError,
            AttributeError,
            InvalidSignature,
        ) as exc:
            logger.warning("Operation failed in vault.py: %s", exc, exc_info=True)  # noqa: BLE001

        # Compatibility fallback for Argon2idAESGCM envelopes
        return self._envelope().decrypt_lease(
            encrypted_payload, self._aad(purpose), info=purpose.encode("utf-8")
        )

    def decrypt(self, encrypted_payload: str, *, purpose: str = "secret") -> str:
        """Compatibility helper. Prefer decrypt_lease for zero-after-use behavior."""
        with self.decrypt_lease(encrypted_payload, purpose=purpose) as lease:
            return cast(str, lease.text)

    def export_sealed_bundle(
        self, records: dict[str, str], passphrase: str, *, name: str = "credential-vault"
    ) -> str:
        """Export encrypted records as a sealed, integrity-bound CI/CD bundle."""
        manifest_records = {
            key: {
                "envelope": value,
                "secret_id_sha256": hashlib.sha256(key.encode("utf-8")).hexdigest(),
            }
            for key, value in sorted(records.items())
        }
        self._audit("bundle_export", secret_count=len(records), bundle_name=name)
        return cast(
            str,
            sealed_bundle_encrypt(
                name, manifest_records, passphrase, aad=b"csp:vault:sealed-bundle"
            ),
        )

    def import_sealed_bundle(self, bundle: str | bytes, passphrase: str) -> dict[str, str]:
        """Import a sealed bundle and return encrypted vault records."""
        payload = sealed_bundle_decrypt(bundle, passphrase, aad=b"csp:vault:sealed-bundle")
        imported = {
            key: str(value["envelope"])
            for key, value in payload["records"].items()
            if isinstance(value, dict) and "envelope" in value
        }
        self._audit("bundle_import", secret_count=len(imported))
        return imported


class TargetSecretStore:
    """Manager for target-specific encrypted secrets with thread-safety and background re-rotation."""

    def __init__(self, vault: CyberVault) -> None:
        self._vault = vault
        self._secrets: dict[str, str] = {}
        self._lock = threading.RLock()

        # Background key rotation scheduler (checks every 5 seconds, rotates every 4 hours)
        self._stop_scheduler = threading.Event()
        self._scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self._scheduler_thread.start()

    def _run_scheduler(self) -> None:
        while not self._stop_scheduler.wait(5.0):
            with self._lock:
                try:
                    self.rotate_due_keys()
                except (ValueError, KeyError, InvalidSignature) as exc:
                    logger.debug("Vault background key rotation scheduler failure: %s", exc)

    def close(self) -> None:
        """Stop the background scheduler cleanly."""
        self._stop_scheduler.set()
        if self._scheduler_thread.is_alive():
            self._scheduler_thread.join(timeout=1.0)

    def _secret_id(self, target: str, key: str) -> str:
        return f"{target}:{key}"

    def set_secret(self, target: str, key: str, value: str | bytes) -> None:
        with self._lock:
            rotated = self._vault.rotate_if_due(self._secrets)
            if rotated is not None:
                self._secrets = rotated
            secret_id = self._secret_id(target, key)
            self._secrets[secret_id] = self._vault.encrypt(value, purpose=secret_id)

    @contextmanager
    def lease_secret(self, target: str, key: str) -> Iterator[SecretLease]:
        with self._lock:
            secret_id = self._secret_id(target, key)
            encrypted = self._secrets.get(secret_id)
            if encrypted is None:
                raise KeyError(secret_id)
        with self._vault.decrypt_lease(encrypted, purpose=secret_id) as lease:
            yield lease

    def get_secret(self, target: str, key: str) -> str | None:
        with self._lock:
            secret_id = self._secret_id(target, key)
            encrypted = self._secrets.get(secret_id)
            if not encrypted:
                return None
        return self._vault.decrypt(encrypted, purpose=secret_id)

    def rotate_due_keys(self) -> bool:
        # Performance #5: Do not hold the lock for the entire rotation
        # First, check if rotation is even due
        with self._lock:
            if not self._vault._rotation_policy.is_due(self._vault._rotated_at):
                return False
            records_copy = dict(self._secrets)

        # CPU-intensive rotation happens HERE, outside the lock
        try:
            rotated = self._vault.rotate_key(records_copy)
        except Exception as e:
            logger.error("Vault background rotation failed: %s", e)
            return False

        # Apply results back under lock
        with self._lock:
            self._secrets = rotated
            return True

    def export_sealed_bundle(self, passphrase: str, *, name: str = "target-secret-store") -> str:
        with self._lock:
            return self._vault.export_sealed_bundle(self._secrets, passphrase, name=name)

    def import_sealed_bundle(self, bundle: str | bytes, passphrase: str) -> None:
        with self._lock:
            self._secrets = self._vault.import_sealed_bundle(bundle, passphrase)

    def to_dict(self) -> dict[str, str]:
        with self._lock:
            return dict(self._secrets)

    @classmethod
    def from_dict(cls, vault: CyberVault, data: dict[str, str]) -> TargetSecretStore:
        store = cls(vault)
        with store._lock:
            store._secrets = {str(k): str(v) for k, v in data.items()}
        return store
