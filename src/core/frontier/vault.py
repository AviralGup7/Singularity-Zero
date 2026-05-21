"""
Cyber Security Test Pipeline - hardened credential vault.

Secrets are stored as Argon2id-derived AES-256-GCM envelopes. Access and
rotation events are emitted into the tamper-evident audit chain used by the
dashboard chain-of-custody viewer.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Protocol

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


@dataclass(frozen=True)
class VaultRotationPolicy:
    """Time-based key rotation policy for vault records."""

    interval_seconds: float = 90 * 24 * 3600

    def is_due(self, rotated_at: float) -> bool:
        return (time.time() - rotated_at) >= self.interval_seconds


class CyberVault:
    """Passphrase-backed vault using Argon2id + AES-256-GCM."""

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

    @property
    def key_version(self) -> int:
        return self._key_version

    def _envelope(self) -> Argon2idAESGCM:
        return Argon2idAESGCM(self._master_key, self._kdf_params)

    def _aad(self, purpose: str, key_version: int | None = None) -> bytes:
        payload = {
            "purpose": purpose,
        }
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
            except TypeError:
                pass
        try:
            get_audit_logger().log(
                AuditEventType.SECURITY_EVENT,
                "local",
                self._principal,
                f"credential.{action}",
                result,
                redacted,
            )
        except Exception as e:
            logger.warning("Vault: Audit logging failed: %s", e)

    def rotate_key(self, encrypted_records: dict[str, str] | None = None) -> dict[str, str]:
        """Advance the vault key version and optionally re-encrypt records."""
        records = encrypted_records or {}
        rotated: dict[str, str] = {}
        for secret_id, encrypted in records.items():
            with self.decrypt_lease(encrypted, purpose=secret_id) as lease:
                rotated[secret_id] = self.encrypt(
                    lease.bytes, purpose=secret_id, key_version=self._key_version + 1
                )
        self._key_version += 1
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
        """Encrypt plaintext and return an Argon2id/AES-GCM envelope."""
        version = key_version or self._key_version
        raw = data if isinstance(data, bytes) else data.encode("utf-8")
        try:
            encrypted = self._envelope().encrypt(
                raw, self._aad(purpose, version), info=purpose.encode("utf-8")
            )
            self._audit("store", secret_id=purpose, key_version=version)
            return encrypted
        finally:
            secure_wipe(bytearray(raw))

    def decrypt_lease(self, encrypted_payload: str, *, purpose: str = "secret") -> SecretLease:
        """Decrypt into a lease that wipes the plaintext buffer when released."""
        self._audit("access", secret_id=purpose)
        return self._envelope().decrypt_lease(
            encrypted_payload, self._aad(purpose), info=purpose.encode("utf-8")
        )

    def decrypt(self, encrypted_payload: str, *, purpose: str = "secret") -> str:
        """Compatibility helper. Prefer decrypt_lease for zero-after-use behavior."""
        with self.decrypt_lease(encrypted_payload, purpose=purpose) as lease:
            return lease.text

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
        return sealed_bundle_encrypt(
            name, manifest_records, passphrase, aad=b"csp:vault:sealed-bundle"
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
    """Manager for target-specific encrypted secrets."""

    def __init__(self, vault: CyberVault) -> None:
        self._vault = vault
        self._secrets: dict[str, str] = {}

    def _secret_id(self, target: str, key: str) -> str:
        return f"{target}:{key}"

    def set_secret(self, target: str, key: str, value: str | bytes) -> None:
        rotated = self._vault.rotate_if_due(self._secrets)
        if rotated is not None:
            self._secrets = rotated
        secret_id = self._secret_id(target, key)
        self._secrets[secret_id] = self._vault.encrypt(value, purpose=secret_id)

    @contextmanager
    def lease_secret(self, target: str, key: str) -> Iterator[SecretLease]:
        secret_id = self._secret_id(target, key)
        encrypted = self._secrets.get(secret_id)
        if encrypted is None:
            raise KeyError(secret_id)
        with self._vault.decrypt_lease(encrypted, purpose=secret_id) as lease:
            yield lease

    def get_secret(self, target: str, key: str) -> str | None:
        secret_id = self._secret_id(target, key)
        encrypted = self._secrets.get(secret_id)
        if not encrypted:
            return None
        return self._vault.decrypt(encrypted, purpose=secret_id)

    def rotate_due_keys(self) -> bool:
        rotated = self._vault.rotate_if_due(self._secrets)
        if rotated is None:
            return False
        self._secrets = rotated
        return True

    def export_sealed_bundle(self, passphrase: str, *, name: str = "target-secret-store") -> str:
        return self._vault.export_sealed_bundle(self._secrets, passphrase, name=name)

    def import_sealed_bundle(self, bundle: str | bytes, passphrase: str) -> None:
        self._secrets = self._vault.import_sealed_bundle(bundle, passphrase)

    def to_dict(self) -> dict[str, str]:
        return dict(self._secrets)

    @classmethod
    def from_dict(cls, vault: CyberVault, data: dict[str, str]) -> TargetSecretStore:
        store = cls(vault)
        store._secrets = dict(data)
        return store
