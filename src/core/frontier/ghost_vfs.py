"""
Cyber Security Test Pipeline - Ghost-VFS
RAM-only Volatile Virtual File System for anti-forensic scan artifacts.
"""

from __future__ import annotations

import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class GhostVFS:
    """
    Volatile Encrypted Storage.
    Maintains all scan artifacts (subdomains.txt, findings.json, etc.) in RAM.
    Data is encrypted with a session-only key.
    Replaces physical disk output for high-security environments.
    """

    def __init__(self) -> None:
        self._files: dict[str, bytes] = {}
        self._key = AESGCM.generate_key(bit_length=256)
        self._aesgcm = AESGCM(self._key)
        logger.info("Ghost-VFS Initialized (Anti-Forensic Mode: ACTIVE)")

    def write_file(self, path: str, content: str | bytes) -> None:
        """Encrypt and store file content in RAM."""
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

        # Fix Audit #9: Securely wipe the key from memory
        # Fix #207: Python bytes are immutable. True secure wipe of bytes is
        # impossible without C-extensions. We overwrite references to encourage GC.
        if hasattr(self, "_key") and isinstance(self._key, bytes):
            try:
                # Overwrite with random bytes before reassignment
                # Note: Python's immutable bytes makes this tricky, but we can
                # at least minimize the window and clear the reference.
                # In a real C-extension we would use memset(0).
                # Here we overwrite the reference with a fresh random buffer
                # to encourage GC of the old one and avoid leaving it as b""
                length = len(self._key)
                self._key = secrets.token_bytes(length)
                self._key = b"\x00" * length
            except Exception as e:
                # Fix #208: Add logger.debug instead of bare pass
                logger.debug("Ghost-VFS: Key wipe attempt failed: %s", e)

        self._key = b""
        logger.warning("Ghost-VFS: Data plane PURGED")
