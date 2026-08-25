"""Content-Addressed Storage (CAS) and Merkle Evidence Binding Engine.

Implements Content-Addressed Storage (CAS) for out-of-band evidence storage:
- Evidence payloads are addressed by SHA-256 hash
- Claims cryptographically bind evidence via SHA-256 Merkle roots (Invariant I27)
- Raft entries store only CAS Merkle roots and hash references, keeping entries < 64 KB
- Lookup fails closed with missing blob / checksum mismatch detection
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def compute_sha256(data: bytes | str) -> str:
    """Compute standard hexadecimal SHA-256 digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_merkle_root(leaf_hashes: Sequence[str]) -> str:
    """Compute binary SHA-256 Merkle tree root over an ordered list of leaf hashes (I27)."""
    from src.core.security.merkle import merkle_root_from_leaf_hashes

    return merkle_root_from_leaf_hashes(leaf_hashes)


@dataclass(frozen=True, slots=True)
class CASBlob:
    """Immutable Content-Addressed Storage blob."""

    blob_hash: str
    size_bytes: int
    content_type: str = "application/octet-stream"
    metadata: Mapping[str, Any] = field(default_factory=dict)


class CASStorageError(RuntimeError):
    """Raised when CAS evidence storage or verification fails."""


class CASStore:
    """Thread-safe Content-Addressed Storage for scan evidence and proof artifacts."""

    def __init__(self, root_dir: str | Path | None = None) -> None:
        self.root_dir = Path(root_dir) if root_dir else None
        if self.root_dir:
            self.root_dir.mkdir(parents=True, exist_ok=True)
        self._memory_blobs: dict[str, bytes] = {}
        self._blob_metadata: dict[str, CASBlob] = {}
        self._lock = threading.RLock()

    def store_blob(
        self,
        data: bytes | str,
        content_type: str = "application/octet-stream",
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        """Store a data blob and return its SHA-256 content address."""
        if isinstance(data, str):
            data = data.encode("utf-8")

        blob_hash = compute_sha256(data)
        blob_meta = CASBlob(
            blob_hash=blob_hash,
            size_bytes=len(data),
            content_type=content_type,
            metadata=dict(metadata or {}),
        )

        with self._lock:
            self._memory_blobs[blob_hash] = data
            self._blob_metadata[blob_hash] = blob_meta

            if self.root_dir:
                prefix = blob_hash[:2]
                blob_dir = self.root_dir / prefix
                blob_dir.mkdir(parents=True, exist_ok=True)
                blob_path = blob_dir / blob_hash
                if not blob_path.exists():
                    tmp_path = blob_dir / f"{blob_hash}.tmp.{os.getpid()}"
                    tmp_path.write_bytes(data)
                    tmp_path.replace(blob_path)

        return blob_hash

    def get_blob(self, blob_hash: str) -> bytes | None:
        """Retrieve blob content with integrity verification (fails closed on hash mismatch)."""
        with self._lock:
            data = self._memory_blobs.get(blob_hash)
            if data is None and self.root_dir:
                prefix = blob_hash[:2]
                blob_path = self.root_dir / prefix / blob_hash
                if blob_path.exists():
                    data = blob_path.read_bytes()
                    self._memory_blobs[blob_hash] = data

            if data is not None:
                # Verify content hash (fail-closed invariant)
                actual_hash = compute_sha256(data)
                if actual_hash != blob_hash:
                    logger.error(
                        "CAS corruption detected: expected %s, got %s", blob_hash, actual_hash
                    )
                    raise CASStorageError(
                        f"CAS integrity violation: hash mismatch for blob {blob_hash}"
                    )
                return data

            return None

    def has_blob(self, blob_hash: str) -> bool:
        """Check if blob exists and is readable."""
        with self._lock:
            if blob_hash in self._memory_blobs:
                return True
            if self.root_dir:
                prefix = blob_hash[:2]
                return (self.root_dir / prefix / blob_hash).exists()
            return False

    def compute_merkle_root(self, leaf_hashes: Sequence[str]) -> str:
        """Compute binary SHA-256 Merkle root over ordered leaf hashes."""
        return compute_merkle_root(leaf_hashes)

    def verify_merkle_root(self, leaf_hashes: Sequence[str], expected_root: str) -> bool:
        """Verify that leaf hashes form the expected Merkle root and that all blobs exist."""
        if not expected_root:
            return False
        computed_root = compute_merkle_root(leaf_hashes)
        if computed_root != expected_root:
            return False

        # Fail closed if any leaf blob is missing
        with self._lock:
            for lh in leaf_hashes:
                if not self.has_blob(lh):
                    logger.warning("CAS verification failed: missing leaf blob %s", lh)
                    return False
        return True


# Global singleton instance for shared process lifecycle
_GLOBAL_CAS_STORE: CASStore | None = None
_GLOBAL_CAS_LOCK = threading.Lock()


def get_global_cas_store(root_dir: str | Path | None = None) -> CASStore:
    global _GLOBAL_CAS_STORE
    with _GLOBAL_CAS_LOCK:
        if _GLOBAL_CAS_STORE is None:
            _GLOBAL_CAS_STORE = CASStore(root_dir=root_dir)
        return _GLOBAL_CAS_STORE
