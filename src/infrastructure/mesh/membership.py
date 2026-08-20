"""Cluster membership: who is alive and what work they own.

This is the coordinator's source of truth for mesh membership. It is
intentionally scanner-agnostic — a member is a node id, an incarnation,
a lifecycle status, and a set of opaque work ids.

Invariant
---------
After any finite sequence of joins, leaves, crashes, rejoins, stale
age-outs, duplicate updates, and concurrent merges, every replica
converges to the same set of **alive** members and the same
``work_id -> owner`` map. Each work id has at most one owner.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Literal

MemberStatus = Literal["alive", "suspect", "dead", "left"]

_STATUS_RANK: dict[str, int] = {
    "alive": 0,
    "suspect": 1,
    "left": 2,
    "dead": 3,
}

_ALIVE_STATUSES = frozenset({"alive", "suspect"})


@dataclass
class MemberRecord:
    """One node's membership + work-ownership record."""

    node_id: str
    incarnation: int = 0
    status: MemberStatus = "alive"
    owned_work: frozenset[str] = field(default_factory=frozenset)
    last_seen: float = field(default_factory=time.time)
    version: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "incarnation": self.incarnation,
            "status": self.status,
            "owned_work": sorted(self.owned_work),
            "last_seen": self.last_seen,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MemberRecord:
        work = data.get("owned_work") or ()
        status = str(data.get("status") or "alive")
        if status not in _STATUS_RANK:
            status = "alive"
        try:
            incarnation = int(data.get("incarnation") or 0)
        except (TypeError, ValueError):
            incarnation = 0
        try:
            version = int(data.get("version") or 0)
        except (TypeError, ValueError):
            version = 0
        try:
            last_seen = float(data.get("last_seen") or 0.0)
        except (TypeError, ValueError):
            last_seen = 0.0
        return cls(
            node_id=str(data.get("node_id") or data.get("id") or ""),
            incarnation=incarnation,
            status=status,  # type: ignore[arg-type]
            owned_work=frozenset(str(item) for item in work if item),
            last_seen=last_seen,
            version=version,
        )


def _sort_key(record: MemberRecord) -> tuple[int, int, float, str]:
    return (record.incarnation, record.version, record.last_seen, record.node_id)


def merge_member(left: MemberRecord, right: MemberRecord) -> MemberRecord:
    """SWIM-style merge of two records for the same node id."""
    if left.node_id != right.node_id:
        raise ValueError("cannot merge membership records for different nodes")
    if left.incarnation != right.incarnation:
        winner = left if left.incarnation > right.incarnation else right
        return MemberRecord(
            node_id=winner.node_id,
            incarnation=winner.incarnation,
            status=winner.status,
            owned_work=winner.owned_work,
            last_seen=max(left.last_seen, right.last_seen),
            version=winner.version,
        )
    left_rank = _STATUS_RANK.get(left.status, 0)
    right_rank = _STATUS_RANK.get(right.status, 0)
    if left_rank != right_rank:
        winner = left if left_rank > right_rank else right
    elif left.version != right.version:
        winner = left if left.version > right.version else right
    else:
        winner = left if left.last_seen >= right.last_seen else right
    work = winner.owned_work
    if winner.status not in _ALIVE_STATUSES:
        work = frozenset()
    return MemberRecord(
        node_id=left.node_id,
        incarnation=max(left.incarnation, right.incarnation),
        status=winner.status,
        owned_work=work,
        last_seen=max(left.last_seen, right.last_seen),
        version=max(left.version, right.version),
    )


class ClusterMembership:
    """Thread-safe, mergeable view of cluster membership and work ownership."""

    def __init__(self, *, clock: Any = time.time) -> None:
        self._clock = clock
        self._lock = threading.RLock()
        self._members: dict[str, MemberRecord] = {}

    def join(
        self,
        node_id: str,
        *,
        owned_work: list[str] | tuple[str, ...] | set[str] | frozenset[str] | None = None,
        now: float | None = None,
    ) -> MemberRecord:
        """Register or refresh a live node. Duplicate joins are idempotent.

        ``owned_work=None`` keeps the existing set (heartbeat). Pass an
        empty collection to explicitly drop all work.
        """
        node_id = str(node_id)
        if not node_id:
            raise ValueError("node_id is required")
        stamp = float(now if now is not None else self._clock())
        work = None if owned_work is None else frozenset(str(item) for item in owned_work if item)
        with self._lock:
            existing = self._members.get(node_id)
            if existing is None:
                record = MemberRecord(
                    node_id=node_id,
                    incarnation=0,
                    status="alive",
                    owned_work=work or frozenset(),
                    last_seen=stamp,
                    version=1,
                )
            elif existing.status in {"dead", "left"}:
                record = MemberRecord(
                    node_id=node_id,
                    incarnation=existing.incarnation + 1,
                    status="alive",
                    owned_work=work if work is not None else frozenset(),
                    last_seen=stamp,
                    version=existing.version + 1,
                )
            else:
                record = MemberRecord(
                    node_id=node_id,
                    incarnation=existing.incarnation,
                    status="alive",
                    owned_work=existing.owned_work if work is None else work,
                    last_seen=stamp,
                    version=existing.version + 1,
                )
            self._members[node_id] = record
            self._resolve_work_conflicts_unlocked()
            return self._members[node_id]

    def leave(self, node_id: str, *, now: float | None = None) -> MemberRecord | None:
        """Graceful departure: member is gone and no longer owns work."""
        return self._terminal(node_id, "left", now=now)

    def crash(self, node_id: str, *, now: float | None = None) -> MemberRecord | None:
        """Unexpected death: member is dead and work is orphaned."""
        return self._terminal(node_id, "dead", now=now)

    def rejoin(
        self,
        node_id: str,
        *,
        owned_work: list[str] | tuple[str, ...] | set[str] | frozenset[str] = (),
        now: float | None = None,
    ) -> MemberRecord:
        """Force a new incarnation after a crash or leave."""
        node_id = str(node_id)
        stamp = float(now if now is not None else self._clock())
        work = frozenset(str(item) for item in owned_work if item)
        with self._lock:
            existing = self._members.get(node_id)
            incarnation = (existing.incarnation + 1) if existing is not None else 1
            version = (existing.version + 1) if existing is not None else 1
            record = MemberRecord(
                node_id=node_id,
                incarnation=incarnation,
                status="alive",
                owned_work=work,
                last_seen=stamp,
                version=version,
            )
            self._members[node_id] = record
            self._resolve_work_conflicts_unlocked()
            return record

    def suspect(self, node_id: str, *, now: float | None = None) -> MemberRecord | None:
        with self._lock:
            existing = self._members.get(node_id)
            if existing is None or existing.status in {"dead", "left"}:
                return existing
            stamp = float(now if now is not None else self._clock())
            record = MemberRecord(
                node_id=existing.node_id,
                incarnation=existing.incarnation,
                status="suspect",
                owned_work=existing.owned_work,
                last_seen=existing.last_seen,
                version=existing.version + 1,
            )
            # last_seen stays — suspect is an observation, not a heartbeat
            _ = stamp
            self._members[node_id] = record
            return record

    def claim_work(self, node_id: str, work_id: str, *, now: float | None = None) -> MemberRecord:
        self.join(node_id, now=now)
        with self._lock:
            current = self._members[node_id]
            updated = MemberRecord(
                node_id=current.node_id,
                incarnation=current.incarnation,
                status="alive",
                owned_work=current.owned_work | {str(work_id)},
                last_seen=float(now if now is not None else self._clock()),
                version=current.version + 1,
            )
            self._members[node_id] = updated
            self._resolve_work_conflicts_unlocked()
            return self._members[node_id]

    def release_work(
        self, node_id: str, work_id: str, *, now: float | None = None
    ) -> MemberRecord | None:
        with self._lock:
            existing = self._members.get(node_id)
            if existing is None:
                return None
            updated = MemberRecord(
                node_id=existing.node_id,
                incarnation=existing.incarnation,
                status=existing.status,
                owned_work=existing.owned_work - {str(work_id)},
                last_seen=float(now if now is not None else existing.last_seen),
                version=existing.version + 1,
            )
            self._members[node_id] = updated
            return updated

    def apply_remote(self, record: MemberRecord | dict[str, Any]) -> MemberRecord:
        incoming = record if isinstance(record, MemberRecord) else MemberRecord.from_dict(record)
        if not incoming.node_id:
            raise ValueError("remote membership record missing node_id")
        with self._lock:
            existing = self._members.get(incoming.node_id)
            merged = incoming if existing is None else merge_member(existing, incoming)
            self._members[incoming.node_id] = merged
            self._resolve_work_conflicts_unlocked()
            return self._members[incoming.node_id]

    def observe_worker(self, worker: Any, *, now: float | None = None) -> MemberRecord:
        """Project a WorkerInfo-like object into membership."""
        node_id = str(getattr(worker, "id", "") or "")
        jobs = list(getattr(worker, "active_jobs", None) or [])
        phase = str(getattr(worker, "phase", "") or getattr(worker, "status", "") or "").lower()
        stamp = float(
            now if now is not None else getattr(worker, "last_heartbeat", None) or self._clock()
        )
        if phase in {"dead"}:
            crashed = self.crash(node_id, now=stamp)
            return crashed or self.join(node_id, now=stamp)
        record = self.join(node_id, owned_work=jobs, now=stamp)
        if phase in {"suspect"}:
            suspected = self.suspect(node_id, now=stamp)
            return suspected or record
        return record

    def age_out(
        self,
        *,
        now: float | None = None,
        suspect_after: float = 45.0,
        dead_after: float = 90.0,
    ) -> list[str]:
        """Mark silent members suspect, then dead. Returns newly-dead ids."""
        stamp = float(now if now is not None else self._clock())
        newly_dead: list[str] = []
        with self._lock:
            for node_id, record in list(self._members.items()):
                if record.status in {"dead", "left"}:
                    continue
                age = stamp - float(record.last_seen or 0.0)
                if age >= dead_after:
                    self._members[node_id] = MemberRecord(
                        node_id=record.node_id,
                        incarnation=record.incarnation,
                        status="dead",
                        owned_work=frozenset(),
                        last_seen=record.last_seen,
                        version=record.version + 1,
                    )
                    newly_dead.append(node_id)
                elif age >= suspect_after and record.status != "suspect":
                    self._members[node_id] = MemberRecord(
                        node_id=record.node_id,
                        incarnation=record.incarnation,
                        status="suspect",
                        owned_work=record.owned_work,
                        last_seen=record.last_seen,
                        version=record.version + 1,
                    )
        return newly_dead

    def merge(self, other: ClusterMembership) -> ClusterMembership:
        """Return a new view that is the least upper bound of ``self`` and ``other``."""
        result = ClusterMembership(clock=self._clock)
        with self._lock:
            local = dict(self._members)
        with other._lock:
            remote = dict(other._members)
        ids = set(local) | set(remote)
        for node_id in ids:
            left = local.get(node_id)
            right = remote.get(node_id)
            if left is None:
                result._members[node_id] = right  # type: ignore[assignment]
            elif right is None:
                result._members[node_id] = left
            else:
                result._members[node_id] = merge_member(left, right)
        result._resolve_work_conflicts_unlocked()
        return result

    def apply_all(self, other: ClusterMembership) -> None:
        """Merge ``other`` into this view in place."""
        merged = self.merge(other)
        with self._lock:
            self._members = merged._members

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            members = {node_id: rec.to_dict() for node_id, rec in self._members.items()}
            return {
                "alive": sorted(self.alive_ids()),
                "members": members,
                "owners": dict(self.work_owners()),
            }

    def alive_ids(self) -> set[str]:
        with self._lock:
            return {
                node_id for node_id, rec in self._members.items() if rec.status in _ALIVE_STATUSES
            }

    def work_owners(self) -> dict[str, str]:
        """Map each work id to its single owner. Alive/suspect only."""
        with self._lock:
            return self._owners_unlocked()

    def get(self, node_id: str) -> MemberRecord | None:
        with self._lock:
            return self._members.get(node_id)

    def members(self) -> dict[str, MemberRecord]:
        with self._lock:
            return dict(self._members)

    def _terminal(
        self, node_id: str, status: MemberStatus, *, now: float | None
    ) -> MemberRecord | None:
        node_id = str(node_id)
        stamp = float(now if now is not None else self._clock())
        with self._lock:
            existing = self._members.get(node_id)
            if existing is None:
                record = MemberRecord(
                    node_id=node_id,
                    incarnation=0,
                    status=status,
                    owned_work=frozenset(),
                    last_seen=stamp,
                    version=1,
                )
            else:
                record = MemberRecord(
                    node_id=existing.node_id,
                    incarnation=existing.incarnation,
                    status=status,
                    owned_work=frozenset(),
                    last_seen=stamp,
                    version=existing.version + 1,
                )
            self._members[node_id] = record
            return record

    def _owners_unlocked(self) -> dict[str, str]:
        owners: dict[str, str] = {}
        claimants: dict[str, MemberRecord] = {}
        for rec in self._members.values():
            if rec.status not in _ALIVE_STATUSES:
                continue
            for work_id in rec.owned_work:
                current = claimants.get(work_id)
                if current is None or _sort_key(rec) >= _sort_key(current):
                    claimants[work_id] = rec
                    owners[work_id] = rec.node_id
        return owners

    def _resolve_work_conflicts_unlocked(self) -> None:
        owners = self._owners_unlocked()
        for rec in list(self._members.values()):
            if rec.status not in _ALIVE_STATUSES:
                if rec.owned_work:
                    self._members[rec.node_id] = MemberRecord(
                        node_id=rec.node_id,
                        incarnation=rec.incarnation,
                        status=rec.status,
                        owned_work=frozenset(),
                        last_seen=rec.last_seen,
                        version=rec.version,
                    )
                continue
            kept = frozenset(
                work_id for work_id in rec.owned_work if owners.get(work_id) == rec.node_id
            )
            if kept != rec.owned_work:
                self._members[rec.node_id] = MemberRecord(
                    node_id=rec.node_id,
                    incarnation=rec.incarnation,
                    status=rec.status,
                    owned_work=kept,
                    last_seen=rec.last_seen,
                    version=rec.version,
                )
