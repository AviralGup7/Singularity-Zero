from __future__ import annotations

from src.auth import (
    AuthAuditAction,
    AuthAuditLog,
    Capability,
    SessionKind,
    SessionRegistry,
    can,
    describe,
    matrix_capabilities,
)


def test_registry_issues_jwt_and_resolves_bearer() -> None:
    registry = SessionRegistry(ttl_seconds=120)
    session = registry.issue_jwt("ada", "analyst")
    assert session.kind is SessionKind.JWT
    assert session.has_bearer_token
    assert registry.resolve_bearer(session.bearer_token or "") is session
    assert describe(session)["demo"] is False


def test_demo_has_no_bearer_and_analyst_can_launch() -> None:
    registry = SessionRegistry()
    demo = registry.issue_demo("Ada", "analyst")
    assert demo.bearer_token is None
    assert can("analyst", Capability.LAUNCH_JOBS.value)
    assert Capability.MANAGE_USERS.value not in matrix_capabilities("analyst")
    assert can("admin", Capability.MANAGE_USERS.value)


def test_audit_log_tracks_demo_logins() -> None:
    log = AuthAuditLog()
    registry = SessionRegistry()
    demo = registry.issue_demo()
    log.record(AuthAuditAction.LOGIN, demo)
    log.record(AuthAuditAction.DENY, demo, detail="missing cap")
    assert log.demo_logins() == 1
    assert len(log.denials()) == 1
