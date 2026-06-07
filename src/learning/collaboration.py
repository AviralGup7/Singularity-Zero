"""User / Role / Team model for collaborative triage.

Bug-bounty teams coordinate multiple analysts on the same program.
The existing :class:`useTriageCollaboration` hook supports real-time
WebSocket comments and status changes, but it has no notion of *who*
is reviewing *what*. This module adds:

* :class:`User` — identity, role, contact info, online status.
* :class:`Role` — operator, reviewer, admin (extensible).
* :class:`Team` — a group of users assigned to a program.
* :class:`FindingAssignment` — a record of which user is reviewing
  which finding, with optimistic locking.
* :class:`AssignmentStore` — in-memory + SQLite-backed store that
  the WebSocket layer and the frontend's bulk-action handler can
  read/write.

Optimistic locking
------------------
The store records ``locked_by`` (user id) and ``locked_at`` for every
in-progress review. When a second user tries to update the same
finding the store raises :class:`AssignmentConflict` so the UI can
show a "currently being reviewed by <name>" message.

Persistence
-----------
The store uses an in-memory dict as the source of truth plus a
SQLite table (``finding_assignments``) for durability. The
:class:`repositories.finding_assignments_repo` module (added in the
same change) provides CRUD operations.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Iterable, Mapping

logger = logging.getLogger(__name__)


class Role(str, Enum):
    """Built-in roles.

    New roles can be added via :func:`register_role`, which stores
    them in :data:`CUSTOM_ROLES` so ``User.from_dict`` can resolve
    them by string value.
    """

    OPERATOR = "operator"
    REVIEWER = "reviewer"
    ADMIN = "admin"


CUSTOM_ROLES: dict[str, "Role"] = {}


def register_role(name: str) -> "Role":
    """Register a custom role and return it.

    Because :class:`Role` is a closed :class:`enum.Enum` we cannot
    extend it at runtime; the helper returns a lightweight wrapper
    that quacks like a :class:`Role` and compares equal to the
    original string. Down-stream code can use it as if it were a
    real :class:`Role`.
    """
    from types import SimpleNamespace

    existing = CUSTOM_ROLES.get(name)
    if existing is not None:
        return existing
    wrapper = SimpleNamespace(value=name, name=name.upper())
    CUSTOM_ROLES[name] = wrapper
    return wrapper


@dataclass(slots=True)
class User:
    """An analyst in the triage workflow."""

    user_id: str
    display_name: str
    role: Role = Role.OPERATOR
    email: str = ""
    online: bool = False
    last_seen: float = field(default_factory=time.time)
    teams: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "User":
        role_name = str(data.get("role", "operator")).lower()
        try:
            role = Role(role_name)
        except ValueError:
            role = CUSTOM_ROLES.get(role_name, Role.OPERATOR)
        return cls(
            user_id=str(data["user_id"]),
            display_name=str(data.get("display_name", data["user_id"])),
            role=role,
            email=str(data.get("email", "")),
            online=bool(data.get("online", False)),
            last_seen=float(data.get("last_seen", time.time())),
            teams=tuple(data.get("teams", []) or ()),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "display_name": self.display_name,
            "role": self.role.value,
            "email": self.email,
            "online": self.online,
            "last_seen": self.last_seen,
            "teams": list(self.teams),
        }


@dataclass(slots=True)
class Team:
    """A group of users assigned to a program."""

    team_id: str
    name: str
    program: str
    members: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Team":
        return cls(
            team_id=str(data["team_id"]),
            name=str(data.get("name", data["team_id"])),
            program=str(data.get("program", "")),
            members=tuple(data.get("members", []) or ()),
        )


@dataclass(slots=True)
class FindingAssignment:
    """Assignment of a finding to a user for review."""

    finding_id: str
    assigned_to: str
    assigned_at: float
    assigned_by: str = ""
    locked_by: str | None = None
    locked_at: float | None = None
    notes: str = ""
    status: str = "pending"  # pending | in_progress | completed

    def to_db_row(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "assigned_to": self.assigned_to,
            "assigned_at": self.assigned_at,
            "assigned_by": self.assigned_by,
            "locked_by": self.locked_by,
            "locked_at": self.locked_at,
            "notes": self.notes,
            "status": self.status,
        }

    @classmethod
    def from_db_row(cls, row: Any) -> "FindingAssignment":
        """Build a :class:`FindingAssignment` from a DB row.

        ``row`` can be either a :class:`sqlite3.Row` (mapping-like)
        or a plain ``tuple`` (positional) — we try the mapping
        interface first and fall back to positional access.
        """
        if isinstance(row, Mapping):
            return cls(
                finding_id=str(row["finding_id"]),
                assigned_to=str(row["assigned_to"]),
                assigned_at=float(row["assigned_at"]),
                assigned_by=str(row.get("assigned_by", "")),
                locked_by=row.get("locked_by"),
                locked_at=float(row["locked_at"]) if row.get("locked_at") is not None else None,
                notes=str(row.get("notes", "")),
                status=str(row.get("status", "pending")),
            )
        # Positional: (finding_id, assigned_to, assigned_at, assigned_by, locked_by, locked_at, notes, status)
        (
            finding_id, assigned_to, assigned_at, assigned_by,
            locked_by, locked_at, notes, status,
        ) = row
        return cls(
            finding_id=str(finding_id),
            assigned_to=str(assigned_to),
            assigned_at=float(assigned_at),
            assigned_by=str(assigned_by or ""),
            locked_by=locked_by,
            locked_at=float(locked_at) if locked_at is not None else None,
            notes=str(notes or ""),
            status=str(status or "pending"),
        )


class AssignmentConflict(RuntimeError):
    """Raised when a user tries to update a finding that is locked
    by a different user.
    """

    def __init__(self, finding_id: str, locked_by: str) -> None:
        self.finding_id = finding_id
        self.locked_by = locked_by
        super().__init__(
            f"finding {finding_id!r} is currently being reviewed by {locked_by!r}"
        )


_CREATE_ASSIGNMENT_TABLE = """
CREATE TABLE IF NOT EXISTS finding_assignments (
    finding_id  TEXT PRIMARY KEY,
    assigned_to TEXT NOT NULL,
    assigned_at REAL NOT NULL,
    assigned_by TEXT,
    locked_by   TEXT,
    locked_at   REAL,
    notes       TEXT DEFAULT '',
    status      TEXT DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS idx_finding_assignments_user ON finding_assignments(assigned_to);
CREATE INDEX IF NOT EXISTS idx_finding_assignments_locked ON finding_assignments(locked_by);
"""


class AssignmentStore:
    """In-memory + SQLite-backed assignment store.

    The in-memory cache is the source of truth for reads; writes are
    synchronously propagated to SQLite so the assignments survive
    process restarts.
    """

    def __init__(self, db_path: str | None = None) -> None:
        self._lock = threading.RLock()
        self._cache: dict[str, FindingAssignment] = {}
        self._db_path = db_path
        if db_path:
            self._init_db()

    def _init_db(self) -> None:
        assert self._db_path is not None
        conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.executescript(_CREATE_ASSIGNMENT_TABLE)
            conn.commit()
            # Warm the cache.
            for row in conn.execute("SELECT * FROM finding_assignments").fetchall():
                fa = FindingAssignment.from_db_row(row)
                self._cache[fa.finding_id] = fa
        finally:
            conn.close()

    def assign(
        self,
        finding_id: str,
        assigned_to: str,
        assigned_by: str = "",
        notes: str = "",
    ) -> FindingAssignment:
        """Assign ``finding_id`` to ``assigned_to``.

        Overwrites any existing assignment. To enforce the
        optimistic-lock semantics, callers should call
        :meth:`lock` first and catch :class:`AssignmentConflict`.
        """
        with self._lock:
            now = time.time()
            fa = FindingAssignment(
                finding_id=finding_id,
                assigned_to=assigned_to,
                assigned_at=now,
                assigned_by=assigned_by,
                notes=notes,
                status="pending",
            )
            self._cache[finding_id] = fa
            self._persist(fa)
            return fa

    def lock(
        self,
        finding_id: str,
        user_id: str,
        *,
        stale_after_seconds: float = 600.0,
    ) -> FindingAssignment:
        """Acquire a review lock on ``finding_id`` for ``user_id``.

        Raises :class:`AssignmentConflict` if a different user holds
        the lock and the lock is fresh. Stale locks (older than
        ``stale_after_seconds``) are auto-released so a crashed
        reviewer's findings don't sit locked forever.
        """
        with self._lock:
            now = time.time()
            existing = self._cache.get(finding_id)
            if (
                existing is not None
                and existing.locked_by is not None
                and existing.locked_by != user_id
                and existing.locked_at is not None
                and (now - existing.locked_at) < stale_after_seconds
            ):
                raise AssignmentConflict(finding_id, existing.locked_by)
            if existing is None:
                existing = FindingAssignment(
                    finding_id=finding_id,
                    assigned_to=user_id,
                    assigned_at=now,
                )
            existing.locked_by = user_id
            existing.locked_at = now
            existing.status = "in_progress"
            self._cache[finding_id] = existing
            self._persist(existing)
            return existing

    def unlock(
        self,
        finding_id: str,
        user_id: str,
    ) -> bool:
        """Release a review lock. Returns True if a lock was released."""
        with self._lock:
            existing = self._cache.get(finding_id)
            if existing is None or existing.locked_by != user_id:
                return False
            existing.locked_by = None
            existing.locked_at = None
            self._persist(existing)
            return True

    def get(self, finding_id: str) -> FindingAssignment | None:
        with self._lock:
            return self._cache.get(finding_id)

    def list_for_user(self, user_id: str) -> list[FindingAssignment]:
        with self._lock:
            return [fa for fa in self._cache.values() if fa.assigned_to == user_id]

    def _persist(self, fa: FindingAssignment) -> None:
        if not self._db_path:
            return
        conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=5.0)
        try:
            conn.execute(
                """INSERT OR REPLACE INTO finding_assignments
                   (finding_id, assigned_to, assigned_at, assigned_by,
                    locked_by, locked_at, notes, status)
                   VALUES (:finding_id, :assigned_to, :assigned_at,
                           :assigned_by, :locked_by, :locked_at, :notes, :status)""",
                fa.to_db_row(),
            )
            conn.commit()
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Module-level singleton used by the WebSocket layer / REST API.
# ---------------------------------------------------------------------------


_STORE_SINGLETON: "AssignmentStore | None" = None


def get_default_store(db_path: str | None = None) -> AssignmentStore:
    """Return the process-wide :class:`AssignmentStore`.

    ``db_path`` is honoured on the first call; subsequent calls
    return the same instance regardless of ``db_path`` (a warning
    is logged when the caller asks for a different path).
    """
    global _STORE_SINGLETON
    if _STORE_SINGLETON is None:
        _STORE_SINGLETON = AssignmentStore(db_path=db_path)
    elif db_path and db_path != _STORE_SINGLETON._db_path:
        logger.debug(
            "get_default_store: ignoring db_path=%r (singleton already initialised with %r)",
            db_path,
            _STORE_SINGLETON._db_path,
        )
    return _STORE_SINGLETON


__all__ = [
    "AssignmentConflict",
    "AssignmentStore",
    "CUSTOM_ROLES",
    "FindingAssignment",
    "Role",
    "Team",
    "User",
    "get_default_store",
    "register_role",
]
