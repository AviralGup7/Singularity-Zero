"""Notification fetch policy.

Demo and guest sessions have no JWT. Hitting ``/api/notifications`` with
them produced 401 toasts after Demo Sign In. Callers must consult this
module instead of assuming every signed-in user has a bearer token.
"""

from __future__ import annotations

from src.auth.policy import requires_bearer_token
from src.auth.session import Session


def should_fetch(session: Session | None, *, bearer_token: str | None = None) -> bool:
    """Return True only when the inbox HTTP API will accept the caller."""
    if bearer_token:
        return True
    return requires_bearer_token(session)


def should_open_stream(session: Session | None, *, bearer_token: str | None = None) -> bool:
    return should_fetch(session, bearer_token=bearer_token)
