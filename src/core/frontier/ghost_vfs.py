"""
Cyber Security Test Pipeline - Ghost-VFS
RAM-only Volatile Virtual File System for anti-forensic scan artifacts.
"""

from __future__ import annotations

import os
import secrets
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.security.encryption import (
    Argon2idAESGCM,
    SecretLease,
    sealed_bundle_decrypt,
    sealed_bundle_encrypt,
    secure_wipe,
)

logger = get_pipeline_logger(__name__)

# Explicit default key rotation interval (14400 seconds / 4 hours)
DEFAULT_ROTATION_INTERVAL: float = 14400.0


class VFSEncryptionPolicy:
    """Policy engine managing encryption permissions and secure file operations."""

    def __init__(self, role_permissions: dict[str, list[str]] | None = None) -> None:
        self.role_permissions = role_permissions or {
            "admin": ["read", "write", "delete", "export", "import"],
            "system": ["read", "write", "delete", "export", "import"],
            "analyst": ["read"],
            "audit": ["read"],
        }

    def is_allowed(self, principal: str, action: str, path: str) -> bool:
        """Validate if a principal has rights to perform action on a path."""
        allowed_actions = self.role_permissions.get(principal, [])
        if action not in allowed_actions:
            return False

        # Restrict critical paths and file formats to admin or system
        cleaned_path = os.path.normpath(path).lower()
        if "secrets/" in cleaned_path or cleaned_path.endswith((".pem", ".key")):
            return principal in ["admin", "system"]

        return True


class GhostVFS:
    """
    Volatile Encrypted Storage.
    Maintains all scan artifacts (subdomains.txt, findings.json, etc.) in RAM.
    Data is encrypted with a session master key and HKDF-derived subkeys per file.
    Replaces physical disk output for high-security environments.

    Supports temporal key rotation to minimize exposure window.
    """

    def __init__(
        self,
        rotation_interval_hours: float | None = None,
        principal: str = "system",
        policy_engine: VFSEncryptionPolicy | None = None,
    ) -> None:
        self._files: dict[str, bytes] = {}
        self._key = bytearray(AESGCM.generate_key(bit_length=256))
        self._aesgcm = AESGCM(bytes(self._key))

        # Use explicit rotation interval constant if hours not specified
        if rotation_interval_hours is not None:
            self._rotation_interval = rotation_interval_hours * 3600
        else:
            self._rotation_interval = DEFAULT_ROTATION_INTERVAL

        self._last_rotation = time.time()
        self._principal = principal
        self._policy_engine = policy_engine or VFSEncryptionPolicy()

        logger.info(
            "Ghost-VFS Initialized (Anti-Forensic Mode: ACTIVE, Rotation: %.1fs, Principal: %s)",
            self._rotation_interval,
            self._principal,
        )

    def write_file(self, path: str, content: str | bytes) -> None:
        """Encrypt and store file content in RAM."""
        data = content if isinstance(content, bytes) else content.encode()
        self.write_file_stream(path, iter([data]))

    def write_file_stream(self, path: str, stream: Iterator[bytes]) -> None:
        """Encrypt and store file content in RAM via chunked stream."""
        cleaned_path = os.path.normpath(path)
        if (
            cleaned_path.startswith("..")
            or os.path.isabs(cleaned_path)
            or cleaned_path.startswith(("/", "\\"))
            or (len(cleaned_path) > 1 and cleaned_path[1] == ":")
        ):
            raise ValueError(f"Ghost-VFS: Invalid virtual path: {path}")

        # Policy enforcement
        if not self._policy_engine.is_allowed(self._principal, "write", path):
            raise PermissionError(
                f"Ghost-VFS: Principal '{self._principal}' is not allowed to write '{path}'"
            )

        # Proactive rotation check on write
        if time.time() - self._last_rotation > self._rotation_interval:
            self.rotate_key()

        salt = os.urandom(16)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=path.encode("utf-8"),
        )
        file_key = bytearray(hkdf.derive(bytes(self._key)))

        payload_parts = [salt]
        try:
            for idx, chunk in enumerate(stream):
                nonce = os.urandom(12)
                # Associated data prevents block reordering/injection attacks
                aad = f"chunk:{idx}".encode()
                ciphertext = AESGCM(bytes(file_key)).encrypt(nonce, chunk, aad)
                chunk_payload = nonce + ciphertext
                length_bytes = len(chunk_payload).to_bytes(4, byteorder="big")
                payload_parts.append(length_bytes + chunk_payload)
        finally:
            secure_wipe(file_key)

        self._files[path] = b"".join(payload_parts)

    def read_file(self, path: str) -> bytes:
        """Decrypt and retrieve file from RAM."""
        return b"".join(self.read_file_stream(path))

    def read_file_stream(self, path: str) -> Iterator[bytes]:
        """Decrypt and retrieve file from RAM via chunked streaming iterator."""
        cleaned_path = os.path.normpath(path)
        if (
            cleaned_path.startswith("..")
            or os.path.isabs(cleaned_path)
            or cleaned_path.startswith(("/", "\\"))
            or (len(cleaned_path) > 1 and cleaned_path[1] == ":")
        ):
            raise ValueError(f"Ghost-VFS: Invalid virtual path: {path}")

        # Policy enforcement
        if not self._policy_engine.is_allowed(self._principal, "read", path):
            raise PermissionError(
                f"Ghost-VFS: Principal '{self._principal}' is not allowed to read '{path}'"
            )

        raw = self._files.get(path)
        if not raw:
            raise FileNotFoundError(f"Ghost-VFS: {path} not found")

        if len(raw) < 16:
            raise ValueError("Ghost-VFS: Corrupt virtual file (too small)")

        salt = raw[:16]
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=path.encode("utf-8"),
        )
        file_key = bytearray(hkdf.derive(bytes(self._key)))

        try:
            offset = 16
            idx = 0
            while offset < len(raw):
                if offset + 4 > len(raw):
                    raise ValueError("Ghost-VFS: Corrupt chunk length header")
                length = int.from_bytes(raw[offset : offset + 4], byteorder="big")
                offset += 4

                if offset + length > len(raw):
                    raise ValueError("Ghost-VFS: Corrupt chunk payload")
                chunk_payload = raw[offset : offset + length]
                offset += length

                nonce = chunk_payload[:12]
                ciphertext = chunk_payload[12:]
                aad = f"chunk:{idx}".encode()

                decrypted_chunk = AESGCM(bytes(file_key)).decrypt(nonce, ciphertext, aad)
                yield decrypted_chunk
                idx += 1
        finally:
            secure_wipe(file_key)

    @contextmanager
    def lease_file(self, path: str) -> Iterator[SecretLease]:
        """Read a file through a wiping plaintext lease."""
        data = self.read_file(path)
        try:
            with SecretLease(data) as lease:
                yield lease
        finally:
            secure_wipe(bytearray(data))

    def rotate_key(self) -> None:
        """
        Generate a fresh key and re-encrypt all stored artifacts.
        Securely attempts to wipe the old key from memory.
        """
        logger.info("Ghost-VFS: Initiating temporal key rotation...")
        start_ts = time.monotonic()

        # Phase 1: Pre-decrypt all files to ensure we don't lose data on any failure
        decrypted_data: dict[str, bytes] = {}
        try:
            for path in list(self._files.keys()):
                decrypted_data[path] = self.read_file(path)
        except Exception as e:
            logger.error("Ghost-VFS: Failed to decrypt %s during rotation prep: %s", path, e)
            # Wipe what we have decrypted so far to avoid memory leak
            for decrypted_bytes in decrypted_data.values():
                secure_wipe(bytearray(decrypted_bytes))
            raise RuntimeError(f"Key rotation aborted: failed to decrypt {path}") from e

        old_key = self._key
        old_aesgcm = self._aesgcm
        new_key = bytearray(AESGCM.generate_key(bit_length=256))

        # Phase 2: Re-encrypt everything with the new key into a temporary dict
        self._key = new_key
        self._aesgcm = AESGCM(bytes(new_key))
        new_files: dict[str, bytes] = {}
        try:
            for path, data in decrypted_data.items():
                try:
                    salt = os.urandom(16)
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        info=path.encode("utf-8"),
                    )
                    file_key = bytearray(hkdf.derive(bytes(new_key)))

                    nonce = os.urandom(12)
                    aad = b"chunk:0"
                    ciphertext = AESGCM(bytes(file_key)).encrypt(nonce, data, aad)
                    chunk_payload = nonce + ciphertext
                    length_bytes = len(chunk_payload).to_bytes(4, byteorder="big")

                    new_files[path] = salt + length_bytes + chunk_payload
                except Exception as e:
                    logger.error("Ghost-VFS: Failed to re-encrypt %s during rotation: %s", path, e)
                    raise RuntimeError(f"Key rotation aborted: failed to encrypt {path}") from e
                finally:
                    secure_wipe(file_key)
        except Exception:
            self._key = old_key
            self._aesgcm = old_aesgcm
            secure_wipe(new_key)
            raise
        finally:
            # Wiping standard decrypted plaintext memory
            for decrypted_bytes in decrypted_data.values():
                secure_wipe(bytearray(decrypted_bytes))

        # Phase 3: Update state (Atomic swap)
        self._files = new_files
        self._last_rotation = time.time()

        # Wipe old key
        self._secure_wipe_bytes(old_key)

        duration = time.monotonic() - start_ts
        logger.info(
            "Ghost-VFS: Key rotation complete. %d files re-encrypted in %.3fs",
            len(new_files),
            duration,
        )

    def _secure_wipe_bytes(self, b: bytearray | bytes | None) -> None:
        """Attempt to clear bytes/bytearray from memory securely."""
        if not b:
            return
        if isinstance(b, bytearray):
            secure_wipe(b)
        elif isinstance(b, bytes):
            try:
                # Immutable bytes can't be cleared in place, but we try to delete reference
                del b
            except Exception as e:
                logger.warning("Ghost-VFS: Diagnostic warning in secure wipe bytes: %s", e)

    def list_files(self) -> list[str]:
        """List all files in the virtual filesystem."""
        return list(self._files.keys())

    def flush_to_disk(self, physical_path: str, master_key: str) -> None:
        """Persist RAM state to disk using Argon2id-derived AES-256-GCM envelopes."""
        logger.info("Ghost-VFS: Flushing volatile state to %s", physical_path)

        # Canonicalize base path
        base_abs = os.path.abspath(physical_path)

        count = 0
        for path in self.list_files():
            try:
                # 1. Prevent Path Traversal by checking commonpath
                full_path = os.path.abspath(os.path.join(base_abs, path))
                if os.path.commonpath([base_abs, full_path]) != base_abs:
                    logger.error("Ghost-VFS: Path traversal blocked for path: %s", path)
                    continue

                # Policy enforcement
                if not self._policy_engine.is_allowed(self._principal, "export", path):
                    logger.error("Ghost-VFS: Policy blocked flushing of path: %s", path)
                    continue

                target_dir = os.path.dirname(full_path)
                os.makedirs(target_dir, exist_ok=True)

                with self.lease_file(path) as lease:
                    sealed = Argon2idAESGCM(master_key).encrypt(
                        lease.bytes,
                        f"ghost-vfs:{path}".encode(),
                    )

                fd, temp_file_path = tempfile.mkstemp(
                    dir=target_dir, prefix=".vfs_tmp_", suffix=".tmp"
                )
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(sealed.encode("utf-8"))
                    os.replace(temp_file_path, full_path)
                except Exception:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    if os.path.exists(temp_file_path):
                        try:
                            os.remove(temp_file_path)
                        except Exception:  # noqa: S110
                            pass
                    raise

                count += 1
            except Exception as e:
                logger.error("Ghost-VFS: Failed to flush %s to disk: %s", path, e)

        logger.info("Ghost-VFS: Flush complete. %d artifacts persisted to disk.", count)

    def load_from_disk(self, physical_path: str, master_key: str) -> None:
        """Decrypt physical files and re-hydrate virtual filesystem RAM state."""
        logger.info("Ghost-VFS: Loading volatile state from %s", physical_path)

        base_abs = os.path.abspath(physical_path)

        count = 0
        for root, _, files in os.walk(base_abs):
            for file in files:
                full_path = os.path.abspath(os.path.join(root, file))

                # Prevent Path Traversal by checking commonpath
                if os.path.commonpath([base_abs, full_path]) != base_abs:
                    logger.error(
                        "Ghost-VFS: Path traversal blocked during load for path: %s", full_path
                    )
                    continue

                # Calculate relative virtual path
                rel_path = os.path.relpath(full_path, base_abs).replace("\\", "/")

                # Policy enforcement
                if not self._policy_engine.is_allowed(self._principal, "import", rel_path):
                    logger.error("Ghost-VFS: Policy blocked load of path: %s", rel_path)
                    continue

                try:
                    with open(full_path, "rb") as f:
                        file_content = f.read()

                    if len(file_content) < 28:
                        logger.error(
                            "Ghost-VFS: File %s is too short to contain cryptographic format",
                            rel_path,
                        )
                        continue

                    decrypted = Argon2idAESGCM(master_key).decrypt(
                        file_content,
                        f"ghost-vfs:{rel_path}".encode(),
                    )

                    # Re-hydrate the memory
                    self.write_file(rel_path, decrypted)
                    secure_wipe(bytearray(decrypted))
                    count += 1
                except Exception as e:
                    logger.error("Ghost-VFS: Failed to load/decrypt %s: %s", rel_path, e)

        logger.info("Ghost-VFS: Load complete. %d files re-hydrated.", count)

    def export_sealed_bundle(
        self, output_path: str, master_key: str, *, name: str = "ghost-vfs"
    ) -> None:
        """Export all virtual files as one sealed, integrity-bound bundle."""
        records: dict[str, str] = {}
        for path in self.list_files():
            # Policy enforcement
            if not self._policy_engine.is_allowed(self._principal, "export", path):
                logger.error("Ghost-VFS: Policy blocked bundle export of path: %s", path)
                continue

            with self.lease_file(path) as lease:
                records[path] = Argon2idAESGCM(master_key).encrypt(
                    lease.bytes,
                    f"ghost-vfs-bundle:{path}".encode(),
                )
        bundle = sealed_bundle_encrypt(
            name, records, master_key, aad=b"csp:ghost-vfs:sealed-bundle"
        )
        
        target_dir = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(target_dir, exist_ok=True)
        fd, temp_file_path = tempfile.mkstemp(
            dir=target_dir, prefix=".bundle_tmp_", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(bundle)
            os.replace(temp_file_path, output_path)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            if os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except Exception:
                    pass
            raise

        logger.info(
            "Ghost-VFS: Sealed bundle exported to %s with %d files.", output_path, len(records)
        )

    def import_sealed_bundle(self, bundle_path: str, master_key: str) -> None:
        """Load files from a sealed bundle created for air-gapped runners."""
        with open(bundle_path, encoding="utf-8") as fh:
            payload = sealed_bundle_decrypt(
                fh.read(), master_key, aad=b"csp:ghost-vfs:sealed-bundle"
            )
        for path, encrypted in payload["records"].items():
            cleaned_path = os.path.normpath(str(path))
            if cleaned_path.startswith("..") or os.path.isabs(cleaned_path):
                logger.error(
                    "Ghost-VFS: Path traversal blocked during bundle import for path: %s", path
                )
                continue

            # Policy enforcement
            if not self._policy_engine.is_allowed(self._principal, "import", str(path)):
                logger.error("Ghost-VFS: Policy blocked bundle import of path: %s", path)
                continue

            decrypted = Argon2idAESGCM(master_key).decrypt(
                str(encrypted),
                f"ghost-vfs-bundle:{path}".encode(),
            )
            try:
                self.write_file(str(path), decrypted)
            finally:
                secure_wipe(bytearray(decrypted))

    def self_destruct(self) -> None:
        """Wipe all data and keys from RAM securely."""
        self._files.clear()
        self._secure_wipe_bytes(self._key)
        self._key = b""
        logger.warning("Ghost-VFS: Data plane PURGED")
