"""Auth-adjacent fetch policy used by notifications and other protected APIs."""

from __future__ import annotations

from src.auth.session import Session, SessionKind


def requires_bearer_token(session: Session | None) -> bool:
    """True when the session is allowed to call JWT-gated HTTP APIs."""
    if session is None:
        return False
    if session.kind in {SessionKind.DEMO, SessionKind.GUEST}:
        return False
    return session.has_bearer_token


def is_demo_or_guest(session: Session | None) -> bool:
    if session is None:
        return False
    return session.kind in {SessionKind.DEMO, SessionKind.GUEST}
