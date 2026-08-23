"""Demo-login helpers used by the console runtime."""

from __future__ import annotations

from src.auth.audit import AuthAuditAction, AuthAuditLog
from src.auth.rbac import can_launch
from src.auth.session import Session
from src.auth.sessions import SessionRegistry, describe


def bootstrap_demo(
    registry: SessionRegistry, log: AuthAuditLog, name: str = "Demo Analyst"
) -> Session:
    session = registry.issue_demo(name, "analyst")
    log.record(AuthAuditAction.LOGIN, session, detail="demo")
    return session


def demo_can_start_scans(session: Session) -> bool:
    return can_launch(session) and not session.has_bearer_token


def demo_card(session: Session) -> dict[str, object]:
    payload = describe(session)
    payload["can_start_scans"] = demo_can_start_scans(session)
    return payload
