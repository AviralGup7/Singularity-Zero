from __future__ import annotations

from src.auth import (
    SessionKind,
    capabilities_for_role,
    demo_session,
    guest_session,
    jwt_session,
    requires_bearer_token,
)


def test_demo_analyst_has_audit_logs_and_no_bearer() -> None:
    session = demo_session("Ada", "analyst")
    assert session.kind is SessionKind.DEMO
    assert session.subject == "Ada"
    assert session.allows("viewAuditLogs")
    assert session.bearer_token is None
    assert requires_bearer_token(session) is False


def test_demo_defaults_name_and_role() -> None:
    session = demo_session("")
    assert session.subject == "Demo Analyst"
    assert session.role == "analyst"


def test_guest_cannot_triage() -> None:
    session = guest_session()
    assert session.kind is SessionKind.GUEST
    assert session.allows("viewFindings")
    assert not session.allows("viewAuditLogs")
    assert requires_bearer_token(session) is False


def test_jwt_session_can_call_protected_apis() -> None:
    session = jwt_session("op", "operator", token="abc")
    assert session.has_bearer_token
    assert requires_bearer_token(session) is True


def test_unknown_role_falls_back_to_viewer() -> None:
    caps = capabilities_for_role("not-a-role")
    assert "viewFindings" in caps
    assert "viewAuditLogs" not in caps
