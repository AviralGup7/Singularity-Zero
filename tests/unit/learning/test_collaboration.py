"""Unit tests for the User/Role/Team + optimistic-locking store."""

from __future__ import annotations

import os
import tempfile
import time

import pytest

from src.learning.collaboration import (
    AssignmentConflict,
    AssignmentStore,
    FindingAssignment,
    Role,
    Team,
    User,
    get_default_store,
    register_role,
)


class TestUser:
    def test_to_dict_round_trip(self) -> None:
        u = User(user_id="u1", display_name="Alice", role=Role.REVIEWER, teams=("red",))
        d = u.to_dict()
        again = User.from_dict(d)
        assert again.user_id == "u1"
        assert again.role is Role.REVIEWER
        assert again.teams == ("red",)

    def test_from_dict_unknown_role_falls_back(self) -> None:
        u = User.from_dict({"user_id": "u2", "role": "lead"})
        assert u.role is Role.OPERATOR  # default fallback

    def test_custom_role(self) -> None:
        role = register_role("ghost")
        u = User(user_id="u3", display_name="x", role=role)
        assert u.role.value == "ghost"


class TestTeam:
    def test_from_dict(self) -> None:
        t = Team.from_dict(
            {"team_id": "t1", "name": "Red team", "program": "acme", "members": ["a", "b"]}
        )
        assert t.team_id == "t1"
        assert t.members == ("a", "b")


class TestAssignmentStore:
    def test_assign_and_lock(self) -> None:
        store = AssignmentStore()
        store.assign("f1", "alice", assigned_by="admin")
        store.lock("f1", "alice")
        fa = store.get("f1")
        assert fa is not None
        assert fa.locked_by == "alice"
        assert fa.status == "in_progress"

    def test_lock_conflict_for_other_user(self) -> None:
        store = AssignmentStore()
        store.assign("f1", "alice")
        store.lock("f1", "alice")
        with pytest.raises(AssignmentConflict) as exc:
            store.lock("f1", "bob")
        assert exc.value.finding_id == "f1"
        assert exc.value.locked_by == "alice"

    def test_stale_lock_can_be_taken_over(self) -> None:
        store = AssignmentStore()
        store.assign("f1", "alice")
        store.lock("f1", "alice")
        # Manually backdate the lock.
        fa = store.get("f1")
        assert fa is not None
        fa.locked_at = time.time() - 3600.0
        # Bob can now steal it.
        store.lock("f1", "bob", stale_after_seconds=60.0)
        assert store.get("f1").locked_by == "bob"

    def test_unlock_only_by_holder(self) -> None:
        store = AssignmentStore()
        store.assign("f1", "alice")
        store.lock("f1", "alice")
        assert store.unlock("f1", "bob") is False
        assert store.unlock("f1", "alice") is True
        assert store.get("f1").locked_by is None

    def test_list_for_user(self) -> None:
        store = AssignmentStore()
        store.assign("f1", "alice")
        store.assign("f2", "bob")
        store.assign("f3", "alice")
        result = store.list_for_user("alice")
        assert len(result) == 2
        assert {fa.finding_id for fa in result} == {"f1", "f3"}

    def test_persistence_to_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "assignments.db")
            store1 = AssignmentStore(db_path=db)
            store1.assign("f1", "alice", assigned_by="admin")
            store1.lock("f1", "alice")
            del store1
            # Reopen.
            store2 = AssignmentStore(db_path=db)
            fa = store2.get("f1")
            assert fa is not None
            assert fa.assigned_to == "alice"
            assert fa.locked_by == "alice"
            del store2

    def test_finding_assignment_to_db_row(self) -> None:
        fa = FindingAssignment(
            finding_id="f1",
            assigned_to="alice",
            assigned_at=1.0,
            assigned_by="admin",
            notes="please review",
        )
        row = fa.to_db_row()
        assert row["finding_id"] == "f1"
        again = FindingAssignment.from_db_row(row)
        assert again.finding_id == "f1"
        assert again.assigned_to == "alice"

    def test_singleton_helper(self) -> None:
        a = get_default_store()
        b = get_default_store()
        assert a is b
