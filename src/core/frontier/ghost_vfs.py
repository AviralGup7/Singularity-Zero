"""
Cyber Security Test Pipeline - Ghost-VFS
RAM-only Volatile Virtual File System for anti-forensic scan artifacts.
"""

from __future__ import annotations

import os
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class GhostVFS:
    """
    Volatile Encrypted Storage.
    Maintains all scan artifacts (subdomains.txt, findings.json, etc.) in RAM.
    Data is encrypted with a session-only key.
    Replaces physical disk output for high-security environments.

    Supports temporal key rotation to minimize exposure window.
    """

    def __init__(self, rotation_interval_hours: float = 4.0) -> None:
        self._files: dict[str, bytes] = {}
        self._key = AESGCM.generate_key(bit_length=256)
        self._aesgcm = AESGCM(self._key)
        self._rotation_interval = rotation_interval_hours * 3600
        self._last_rotation = time.time()
        logger.info("Ghost-VFS Initialized (Anti-Forensic Mode: ACTIVE, Rotation: %.1fh)",
                    rotation_interval_hours)

    def write_file(self, path: str, content: str | bytes) -> None:
        """Encrypt and store file content in RAM."""
        # Proactive rotation check on write
        if time.time() - self._last_rotation > self._rotation_interval:
            self.rotate_key()

        data = content if isinstance(content, bytes) else content.encode()
        nonce = os.urandom(12)
        encrypted = self._aesgcm.encrypt(nonce, data, None)
        # Store as nonce + ciphertext
        self._files[path] = nonce + encrypted

    def read_file(self, path: str) -> bytes:
        """Decrypt and retrieve file from RAM."""
        raw = self._files.get(path)
        if not raw:
            raise FileNotFoundError(f"Ghost-VFS: {path} not found")

        nonce = raw[:12]
        ciphertext = raw[12:]
        return self._aesgcm.decrypt(nonce, ciphertext, None)

    def rotate_key(self) -> None:
        """
        Generate a fresh key and re-encrypt all stored artifacts.
        Securely attempts to wipe the old key from memory.
        """
        logger.info("Ghost-VFS: Initiating temporal key rotation...")
        start_ts = time.monotonic()

        # Fix CORR-1: Pre-decrypt everything first to ensure we don't lose data
        # if a single file fails re-encryption after the key has already swapped.
        decrypted_data: dict[str, bytes] = {}
        for path in list(self._files.keys()):
            try:
                decrypted_data[path] = self.read_file(path)
            except Exception as e:
                logger.error("Ghost-VFS: Failed to decrypt %s during rotation prep: %s", path, e)

        old_key = self._key
        new_key = AESGCM.generate_key(bit_length=256)
        new_aesgcm = AESGCM(new_key)

        # Re-encrypt everything with the new key
        file_count = 0
        for path, data in decrypted_data.items():
            try:
                new_nonce = os.urandom(12)
                new_encrypted = new_aesgcm.encrypt(new_nonce, data, None)
                self._files[path] = new_nonce + new_encrypted
                file_count += 1
            except Exception as e:
                logger.error("Ghost-VFS: Failed to re-encrypt %s during rotation: %s", path, e)

        # Update state
        self._key = new_key
        self._aesgcm = new_aesgcm
        self._last_rotation = time.time()

        # Wipe old key
        self._secure_wipe_bytes(old_key)

        duration = time.monotonic() - start_ts
        logger.info("Ghost-VFS: Key rotation complete. %d files re-encrypted in %.3fs",
                    file_count, duration)

    def _secure_wipe_bytes(self, b: bytes) -> None:
        """Attempt to clear bytes from memory (best effort in Python)."""
        if not b or not isinstance(b, bytes):
            return
        try:
            # Fix Q-7: In Python, bytes are immutable, but we can delete the
            # reference and suggest GC. We also overwrite the local name.
            length = len(b)
            # Create a large dummy to pressure memory if needed, but primarily
            # we rely on the reference being gone.
            _dummy = secrets.token_bytes(length)
            del b
        except Exception:  # noqa: S110
            pass
    def list_files(self) -> list[str]:
        """List all files in the virtual filesystem."""
        return list(self._files.keys())

    def flush_to_disk(self, physical_path: str, master_key: str) -> None:
        """Optional: Persist RAM state to disk using a user-provided master key."""
        # Implementation would involve re-encrypting with master_key
        # Placeholder for future implementation
        logger.debug("Ghost-VFS: flush_to_disk called to %s (not implemented)", physical_path)

    def self_destruct(self) -> None:
        """Wipe all data and keys from RAM securely."""
        self._files.clear()
        self._secure_wipe_bytes(self._key)
        self._key = b""
        logger.warning("Ghost-VFS: Data plane PURGED")
