"""Snapshot selection with signed manifest fields (architecture review P0-12).

Never choose "max (commitIndex, term)" alone — require an explicit manifest
binding wal_id, schema_version, and content digest so a corrupt/higher-index
orphan cannot win selection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SnapshotManifest:
    snapshot_id: str
    wal_id: str
    commit_index: int
    term: int
    schema_version: int
    content_digest: str  # hex sha256 of snapshot payload bytes
    signature: str = ""  # hex HMAC over canonical fields
    created_at_unix: float = 0.0

    def canonical_bytes(self) -> bytes:
        payload = {
            "snapshot_id": self.snapshot_id,
            "wal_id": self.wal_id,
            "commit_index": int(self.commit_index),
            "term": int(self.term),
            "schema_version": int(self.schema_version),
            "content_digest": self.content_digest,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, key: bytes) -> SnapshotManifest:
        sig = hmac.new(key, self.canonical_bytes(), hashlib.sha256).hexdigest()
        return SnapshotManifest(
            snapshot_id=self.snapshot_id,
            wal_id=self.wal_id,
            commit_index=self.commit_index,
            term=self.term,
            schema_version=self.schema_version,
            content_digest=self.content_digest,
            signature=sig,
            created_at_unix=self.created_at_unix,
        )

    def verify(self, key: bytes) -> bool:
        if not self.signature:
            return False
        expected = hmac.new(key, self.canonical_bytes(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> SnapshotManifest:
        return cls(
            snapshot_id=str(data.get("snapshot_id") or ""),
            wal_id=str(data.get("wal_id") or ""),
            commit_index=int(data.get("commit_index") or 0),
            term=int(data.get("term") or 0),
            schema_version=int(data.get("schema_version") or 0),
            content_digest=str(data.get("content_digest") or ""),
            signature=str(data.get("signature") or ""),
            created_at_unix=float(data.get("created_at_unix") or 0.0),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "wal_id": self.wal_id,
            "commit_index": self.commit_index,
            "term": self.term,
            "schema_version": self.schema_version,
            "content_digest": self.content_digest,
            "signature": self.signature,
            "created_at_unix": self.created_at_unix,
        }


class SnapshotSelectionError(ValueError):
    """No safe snapshot candidate under manifest rules."""


def select_snapshot(
    candidates: Iterable[SnapshotManifest],
    *,
    verify_key: bytes | None = None,
    require_signature: bool = False,
    max_schema_version: int | None = None,
) -> SnapshotManifest:
    """Pick the best *safe* snapshot.

    Ordering key is (commit_index, term) among candidates that:
      - have non-empty wal_id + content_digest
      - pass HMAC verify when verify_key is provided (or require_signature)
      - schema_version <= max_schema_version when set
    """
    safe: list[SnapshotManifest] = []
    for raw in candidates:
        m = raw if isinstance(raw, SnapshotManifest) else SnapshotManifest.from_mapping(raw)  # type: ignore[arg-type]
        if not m.wal_id or not m.content_digest or not m.snapshot_id:
            continue
        if max_schema_version is not None and int(m.schema_version) > int(max_schema_version):
            continue
        if verify_key is not None:
            if not m.verify(verify_key):
                continue
        elif require_signature and not m.signature:
            continue
        safe.append(m)
    if not safe:
        raise SnapshotSelectionError(
            "no snapshot candidate satisfied manifest binding "
            "(wal_id, content_digest, optional signature/schema gate)"
        )
    safe.sort(key=lambda m: (int(m.commit_index), int(m.term), m.snapshot_id))
    return safe[-1]
