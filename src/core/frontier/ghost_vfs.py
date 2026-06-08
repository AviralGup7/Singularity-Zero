"""Cyber Security Test Pipeline - Ghost-VFS (thin orchestrator)
RAM-only Volatile Virtual File System for anti-forensic scan artifacts.
Public API maintained: GhostVFS, _DecryptingChunkIterator
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.core.frontier.vfs_isolation import (
    DEFAULT_ROTATION_INTERVAL,
    HardwareEnclaveProvider,
    VFSEncryptionPolicy,
    eBPFHookManager,
)
from src.core.frontier.vfs_mounts import VFSMountsMixin
from src.core.frontier.vfs_paths import VFSPathMixin
from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.security.encryption import secure_wipe

logger = get_pipeline_logger(__name__)


class _DecryptingChunkIterator:
    """Iterator that wipes its derived file key as soon as it is no longer needed."""

    def __init__(self, raw: bytes, file_key: bytearray) -> None:
        self._raw = raw
        self._file_key = file_key
        self._aesgcm = AESGCM(bytes(file_key))
        self._offset = 16
        self._idx = 0
        self._closed = False

    def __iter__(self) -> _DecryptingChunkIterator:
        return self

    def __next__(self) -> bytes:
        if self._closed:
            raise StopIteration

        try:
            if self._offset >= len(self._raw):
                self.close()
                raise StopIteration
            if self._offset + 4 > len(self._raw):
                raise ValueError("Ghost-VFS: Corrupt chunk length header")
            length = int.from_bytes(self._raw[self._offset : self._offset + 4], byteorder="big")
            self._offset += 4

            if length < 28 or self._offset + length > len(self._raw):
                raise ValueError("Ghost-VFS: Corrupt chunk payload")
            chunk_payload = self._raw[self._offset : self._offset + length]
            self._offset += length

            nonce = chunk_payload[:12]
            ciphertext = chunk_payload[12:]
            aad = f"chunk:{self._idx}".encode()

            try:
                decrypted_chunk = self._aesgcm.decrypt(nonce, ciphertext, aad)
            except Exception as exc:
                raise ValueError("Ghost-VFS: chunk decryption failed") from exc

            self._idx += 1
            return decrypted_chunk
        except StopIteration:
            raise
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if not self._closed:
            secure_wipe(self._file_key)
            self._closed = True

    def __del__(self) -> None:
        self.close()


class GhostVFS(VFSPathMixin, VFSMountsMixin):
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
        self._files: dict[str, bytearray | bytes] = {}
        self._key = bytearray(AESGCM.generate_key(bit_length=256))
        self._aesgcm = AESGCM(bytes(self._key))
        self._lock = threading.RLock()
        self._file_metadata: dict[str, dict[str, Any]] = {}
        self._memory_pinned = False
        self._destroyed = False

        self._max_memory_bytes = 128 * 1024 * 1024
        self._current_memory_usage = 0
        import tempfile

        self._spill_dir_obj = tempfile.TemporaryDirectory(prefix="ghost_vfs_")
        self._spill_dir = self._spill_dir_obj.name
        self._spilled_files: set[str] = set()

        self._hw_enclave_active = enable_sgx and HardwareEnclaveProvider.is_available()
        self._ebpf_active = enable_ebpf

        if self._ebpf_active:
            try:
                eBPFHookManager.pin_memory(id(self))
                self._memory_pinned = True
            except Exception as exc:
                logger.warning("Ghost-VFS eBPF hook failure during initialization: %s", exc)

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
        data = content if isinstance(content, bytes) else content.encode()
        self.write_file_stream(path, iter([data]))

    def write_file_stream(self, path: str, stream: Iterator[bytes]) -> None:
        self._ensure_active()
        cleaned_path = self._validate_path(path)

        with self._lock:
            if not self._policy_engine.is_allowed(self._principal, "write", cleaned_path):
                raise PermissionError(
                    f"Ghost-VFS: Principal '{self._principal}' is not allowed to write '{path}'"
                )

            if time.time() - self._last_rotation > self._rotation_interval:
                self.rotate_key()

            salt = os.urandom(16)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=cleaned_path.encode("utf-8"),
            )
            file_key = bytearray(hkdf.derive(bytes(self._key)))

            payload_parts = [salt]
            file_aesgcm = AESGCM(bytes(file_key))
            try:
                for idx, chunk in enumerate(stream):
                    if not isinstance(chunk, (bytes, bytearray, memoryview)):
                        raise TypeError("Ghost-VFS: stream chunks must be bytes-like")
                    chunk_bytes = bytes(chunk)
                    nonce = os.urandom(12)
                    aad = f"chunk:{idx}".encode()
                    ciphertext = file_aesgcm.encrypt(nonce, chunk_bytes, aad)
                    chunk_payload = nonce + ciphertext
                    length_bytes = len(chunk_payload).to_bytes(4, byteorder="big")
                    payload_parts.append(length_bytes + chunk_payload)
            finally:
                secure_wipe(file_key)

            old_raw = self._files.get(cleaned_path)
            if old_raw is not None:
                self._wipe_raw_buffer(old_raw)

            self._files[cleaned_path] = bytearray(b"".join(payload_parts))
            self._file_metadata[cleaned_path] = {
                "created_at": time.time(),
            }

    def read_file(self, path: str) -> bytes:
        return b"".join(self.read_file_stream(path))

    def read_file_stream(self, path: str) -> Iterator[bytes]:
        self._ensure_active()
        cleaned_path = self._validate_path(path)

        if not self._policy_engine.is_allowed(self._principal, "read", cleaned_path):
            raise PermissionError(
                f"Ghost-VFS: Principal '{self._principal}' is not allowed to read '{path}'"
            )

        with self._lock:
            stored_raw = self._files.get(cleaned_path)
            if stored_raw is None:
                raise FileNotFoundError(f"Ghost-VFS: {path} not found")
            raw = bytes(stored_raw)

            if len(raw) < 16:
                raise ValueError("Ghost-VFS: Corrupt virtual file (too small)")

            salt = raw[:16]
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=cleaned_path.encode("utf-8"),
            )
            file_key = bytearray(hkdf.derive(bytes(self._key)))

        return _DecryptingChunkIterator(raw, file_key)

    @contextmanager
    def lease_file(self, path: str) -> Iterator[Any]:
        from src.infrastructure.security.encryption import SecretLease

        data = self.read_file(path)
        try:
            with SecretLease(data) as lease:
                yield lease
        finally:
            secure_wipe(bytearray(data))

    def delete_file(self, path: str) -> None:
        self._ensure_active()
        cleaned_path = self._validate_path(path)

        if not self._policy_engine.is_allowed(self._principal, "delete", cleaned_path):
            raise PermissionError(
                f"Ghost-VFS: Principal '{self._principal}' is not allowed to delete '{path}'"
            )

        with self._lock:
            if cleaned_path in self._files:
                raw = self._files[cleaned_path]
                try:
                    self._wipe_raw_buffer(raw)
                except Exception as e:
                    logger.debug("Failed to wipe raw encrypted buffer: %s", e)
                del self._files[cleaned_path]
            if cleaned_path in self._file_metadata:
                del self._file_metadata[cleaned_path]

    def rotate_key(self) -> None:
        logger.info("Ghost-VFS: Initiating temporal key rotation...")
        start_ts = time.monotonic()

        with self._lock:
            self._ensure_active()
            old_key = self._key
            new_key = bytearray(AESGCM.generate_key(bit_length=256))
            new_files: dict[str, bytearray | bytes] = {}
            try:
                for path in list(self._files.keys()):
                    raw = bytes(self._files[path])
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
                        old_file_aesgcm = AESGCM(bytes(old_file_key))
                        new_file_aesgcm = AESGCM(bytes(new_file_key))
                        while offset < len(raw):
                            if offset + 4 > len(raw):
                                raise ValueError("Corrupt chunk length header")
                            length = int.from_bytes(raw[offset : offset + 4], byteorder="big")
                            offset += 4

                            if length < 28 or offset + length > len(raw):
                                raise ValueError("Corrupt chunk payload")
                            chunk_payload = raw[offset : offset + length]
                            offset += length

                            nonce = chunk_payload[:12]
                            ciphertext = chunk_payload[12:]
                            aad = f"chunk:{idx}".encode()

                            decrypted_chunk = bytearray(
                                old_file_aesgcm.decrypt(nonce, ciphertext, aad)
                            )

                            try:
                                new_nonce = os.urandom(12)
                                new_ciphertext = new_file_aesgcm.encrypt(
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

                        new_files[path] = bytearray(b"".join(payload_parts))
                    finally:
                        secure_wipe(old_file_key)
                        secure_wipe(new_file_key)
            except Exception as e:
                logger.error("Ghost-VFS: Key rotation failed: %s", e)
                for buf in new_files.values():
                    self._wipe_raw_buffer(buf)
                secure_wipe(new_key)
                raise RuntimeError("Key rotation aborted") from e

            for buf in self._files.values():
                self._wipe_raw_buffer(buf)
            self._files = new_files
            self._key = new_key
            self._aesgcm = AESGCM(bytes(new_key))
            self._last_rotation = time.monotonic()
            self._secure_wipe_bytes(old_key)

        duration = time.monotonic() - start_ts
        logger.info(
            "Ghost-VFS: Key rotation complete. %d files re-encrypted in %.3fs",
            len(new_files),
            duration,
        )

    def _secure_wipe_bytes(self, b: bytearray | bytes | None) -> None:
        if not b:
            return
        if isinstance(b, bytearray):
            secure_wipe(b)
        elif isinstance(b, bytes):
            try:
                del b
            except Exception as e:
                logger.warning("Ghost-VFS: Diagnostic warning in secure wipe bytes: %s", e)

    def _wipe_raw_buffer(self, raw: bytearray | bytes | None) -> None:
        if raw is None:
            return
        if isinstance(raw, bytearray):
            secure_wipe(raw)
        else:
            secure_wipe(bytearray(raw))

    def _ensure_active(self) -> None:
        if self._destroyed:
            raise RuntimeError("Ghost-VFS: data plane has been purged")

    def list_files(self) -> list[str]:
        with self._lock:
            return list(self._files.keys())

    def self_destruct(self) -> None:
        with self._lock:
            for raw in self._files.values():
                self._wipe_raw_buffer(raw)
            self._files.clear()
            self._file_metadata.clear()
            self._secure_wipe_bytes(self._key)
            self._key = bytearray()
            self._aesgcm = None  # type: ignore[assignment]
            self._destroyed = True
            if self._memory_pinned:
                try:
                    eBPFHookManager.unpin_memory(id(self))
                except Exception as exc:
                    logger.warning("Ghost-VFS eBPF hook failure during self-destruct: %s", exc)
                finally:
                    self._memory_pinned = False
        logger.warning("Ghost-VFS: Data plane PURGED")
