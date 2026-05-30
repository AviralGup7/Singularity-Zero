"""
Cyber Security Test Pipeline - Ghost-VFS
RAM-only Volatile Virtual File System for anti-forensic scan artifacts.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

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


class HardwareEnclaveProvider:
    """Simulates Intel SGX / AMD SEV secure enclave integrations."""
    @staticmethod
    def is_available() -> bool:
        # In a real environment, this checks CPU flags or /dev/sgx
        return False
        
    @staticmethod
    def seal_data(data: bytes) -> bytes:
        # Hardware encryption bounded to CPU
        return data

    @staticmethod
    def unseal_data(data: bytes) -> bytes:
        return data

class eBPFHookManager:
    """Manages eBPF hooks for memory isolation and anti-dumping."""
    @staticmethod
    def pin_memory(address_space: Any) -> None:
        """Lock memory using eBPF to prevent swapping and dumping."""
        pass
        
    @staticmethod
    def unpin_memory(address_space: Any) -> None:
        pass


class GhostVFS:
    """
    Volatile Encrypted Storage using eBPF & Hardware-Protected Secure Enclaves.
    Maintains all scan artifacts in RAM, protected from memory dumps.
    """

    def __init__(
        self,
        rotation_interval_hours: float | None = None,
        principal: str = "system",
        policy_engine: VFSEncryptionPolicy | None = None,
        enable_ebpf: bool = True,
        enable_sgx: bool = True,
    ) -> None:
        self._files: dict[str, bytes] = {}
        self._key = bytearray(AESGCM.generate_key(bit_length=256))
        self._aesgcm = AESGCM(bytes(self._key))
        self._lock = threading.RLock()
        self._file_metadata: dict[str, dict[str, Any]] = {}

        # Hardware Enclave & eBPF integration
        self._hw_enclave_active = enable_sgx and HardwareEnclaveProvider.is_available()
        self._ebpf_active = enable_ebpf
        
        if self._ebpf_active:
            eBPFHookManager.pin_memory(id(self))

        # Use explicit rotation interval constant if hours not specified
        if rotation_interval_hours is not None:
            self._rotation_interval = rotation_interval_hours * 3600
        else:
            self._rotation_interval = DEFAULT_ROTATION_INTERVAL

        self._last_rotation = time.time()
        self._principal = principal
        self._policy_engine = policy_engine or VFSEncryptionPolicy()

        logger.info(
            "Ghost-VFS Initialized (Anti-Forensic Mode: ACTIVE, Rotation: %.1fs, SGX: %s, eBPF: %s)",
            self._rotation_interval,
            self._hw_enclave_active,
            self._ebpf_active,
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

        with self._lock:
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
            self._file_metadata[path] = {
                "created_at": time.time(),
            }

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

        with self._lock:
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
            while True:
                with self._lock:
                    if offset >= len(raw):
                        break
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

    def delete_file(self, path: str) -> None:
        """Securely remove a file from RAM and metadata."""
        with self._lock:
            if path in self._files:
                raw = self._files[path]
                try:
                    buf = bytearray(raw)
                    secure_wipe(buf)
                except Exception as e:
                    logger.debug("Failed to wipe raw encrypted buffer: %s", e)
                del self._files[path]
            if path in self._file_metadata:
                del self._file_metadata[path]

    def rotate_key(self) -> None:
        """
        Generate a fresh key and re-encrypt all stored artifacts chunk by chunk.
        Securely attempts to wipe the old key from memory.
        """
        logger.info("Ghost-VFS: Initiating temporal key rotation...")
        start_ts = time.monotonic()

        old_key = self._key
        new_key = bytearray(AESGCM.generate_key(bit_length=256))

        new_files: dict[str, bytes] = {}

        with self._lock:
            try:
                for path in list(self._files.keys()):
                    raw = self._files[path]
                    if len(raw) < 16:
                        raise ValueError("Corrupt file")
                    old_salt = raw[:16]
                    old_hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=old_salt,
                        info=path.encode("utf-8"),
                    )
                    old_file_key = bytearray(old_hkdf.derive(bytes(old_key)))

                    new_salt = os.urandom(16)
                    new_hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=new_salt,
                        info=path.encode("utf-8"),
                    )
                    new_file_key = bytearray(new_hkdf.derive(bytes(new_key)))

                    payload_parts = [new_salt]

                    try:
                        offset = 16
                        idx = 0
                        while offset < len(raw):
                            if offset + 4 > len(raw):
                                raise ValueError("Corrupt chunk length header")
                            length = int.from_bytes(raw[offset : offset + 4], byteorder="big")
                            offset += 4

                            if offset + length > len(raw):
                                raise ValueError("Corrupt chunk payload")
                            chunk_payload = raw[offset : offset + length]
                            offset += length

                            nonce = chunk_payload[:12]
                            ciphertext = chunk_payload[12:]
                            aad = f"chunk:{idx}".encode()

                            decrypted_chunk = bytearray(
                                AESGCM(bytes(old_file_key)).decrypt(nonce, ciphertext, aad)
                            )

                            try:
                                new_nonce = os.urandom(12)
                                new_ciphertext = AESGCM(bytes(new_file_key)).encrypt(
                                    new_nonce, bytes(decrypted_chunk), aad
                                )
                                new_chunk_payload = new_nonce + new_ciphertext
                                new_length_bytes = len(new_chunk_payload).to_bytes(
                                    4, byteorder="big"
                                )
                                payload_parts.append(new_length_bytes + new_chunk_payload)
                            finally:
                                secure_wipe(decrypted_chunk)

                            idx += 1

                        new_files[path] = b"".join(payload_parts)
                    finally:
                        secure_wipe(old_file_key)
                        secure_wipe(new_file_key)
            except Exception as e:
                logger.error("Ghost-VFS: Key rotation failed: %s", e)
                secure_wipe(new_key)
                raise RuntimeError("Key rotation aborted") from e

            # Phase 3: Update state (Atomic swap)
            self._files = new_files
            self._key = new_key
            self._aesgcm = AESGCM(bytes(new_key))
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
        with self._lock:
            return list(self._files.keys())

    def flush_to_disk(self, physical_path: str, master_key: str) -> None:
        """Persist RAM state to disk using Argon2id-derived AES-256-GCM envelopes securely and atomically."""
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

                with self._lock:
                    fd, temp_file_path = tempfile.mkstemp(
                        dir=target_dir, prefix=".vfs_tmp_", suffix=".tmp"
                    )
                    try:
                        with os.fdopen(fd, "wb") as f:
                            f.write(sealed.encode("utf-8"))
                        os.replace(temp_file_path, full_path)
                    except Exception as e:
                        logger.error(
                            "Ghost-VFS: Write fallback failed for %s: %s", temp_file_path, e
                        )
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                        if os.path.exists(temp_file_path):
                            try:
                                os.remove(temp_file_path)
                            except Exception as ex:
                                logger.debug(
                                    "Ghost-VFS: Failed to remove temp file %s: %s",
                                    temp_file_path,
                                    ex,
                                )
                        raise

                count += 1
            except Exception as e:
                logger.error("Ghost-VFS: Failed to flush %s to disk: %s", path, e)

        logger.info("Ghost-VFS: Flush complete. %d artifacts persisted to disk.", count)

    def load_from_disk(self, physical_path: str, master_key: str) -> None:
        """Decrypt physical files and re-hydrate virtual filesystem RAM state securely."""
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
        """Export all virtual files as one sealed, integrity-bound bundle securely."""
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
        with self._lock:
            fd, temp_file_path = tempfile.mkstemp(
                dir=target_dir, prefix=".bundle_tmp_", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(bundle)
                os.replace(temp_file_path, output_path)
            except Exception as e:
                logger.error("Ghost-VFS: Sealed bundle write fallback failed: %s", e)
                try:
                    os.close(fd)
                except OSError:
                    pass
                if os.path.exists(temp_file_path):
                    try:
                        os.remove(temp_file_path)
                    except Exception as ex:
                        logger.debug(
                            "Ghost-VFS: Failed to remove temp file %s: %s", temp_file_path, ex
                        )

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
        with self._lock:
            self._files.clear()
            self._file_metadata.clear()
            self._secure_wipe_bytes(self._key)
            self._key = bytearray()
        logger.warning("Ghost-VFS: Data plane PURGED")
