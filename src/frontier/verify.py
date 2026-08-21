"""Verify CRDT snapshots used during WAL replay."""

from __future__ import annotations

from typing import Any


def snapshot_sane(snapshot: dict[str, Any] | None) -> bool:
    if not isinstance(snapshot, dict):
        return False
    if snapshot.get("format") not in {None, "neural-state-crdt-v3"} and "sets" not in snapshot:
        # legacy snapshot of lists is still acceptable
        return isinstance(snapshot.get("subdomains"), list) or "findings" in snapshot
    sets = snapshot.get("sets")
    if sets is not None and not isinstance(sets, dict):
        return False
    last = snapshot.get("last_wal_id")
    if last is not None and not isinstance(last, str):
        return False
    return True


def cursor_not_before(left: str | None, right: str | None) -> bool:
    """True when ``left`` is the same as or later than ``right``."""
    if not right:
        return True
    if not left:
        return False
    return _sort_key(left) >= _sort_key(right)


def _sort_key(wal_id: str) -> tuple[float, str]:
    try:
        if wal_id.startswith("aof-"):
            parts = wal_id.split("-", 2)
            return (float(parts[1]) * 1000.0, wal_id)
        head = wal_id.split("-", 1)[0]
        if head.isdigit():
            return (float(head), wal_id)
    except (ValueError, IndexError):
        return (0.0, wal_id)
    return (0.0, wal_id)


def replay_gap(snapshot_cursor: str | None, recovered_ids: list[str]) -> list[str]:
    """Return recovered ids that should have been excluded by the snapshot cursor."""
    if not snapshot_cursor:
        return []
    return [item for item in recovered_ids if _sort_key(item) <= _sort_key(snapshot_cursor)]
