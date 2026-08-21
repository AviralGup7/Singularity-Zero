"""Decide whether the UI should use the console channel or JWT HTTP APIs.

Demo Sign In has no bearer token. Calling ``/api/notifications`` produced
401 toasts. The console channel serves the same inbox locally.
"""

from __future__ import annotations

from src.auth.policy import is_demo_or_guest, requires_bearer_token
from src.auth.session import Session
from src.integration.authz import transport_hints
from src.integration.commands import JWT_NOTIFICATION_PATHS
from src.notifications.policy import should_fetch, should_open_stream


def should_use_console_inbox(session: Session | None, *, bearer_token: str | None = None) -> bool:
    if bearer_token or (session and session.has_bearer_token):
        return False
    return session is not None and is_demo_or_guest(session)


def should_call_jwt_path(
    path: str,
    session: Session | None,
    *,
    bearer_token: str | None = None,
) -> bool:
    normalized = str(path or "").split("?", 1)[0]
    if normalized.rstrip("/") in {item.rstrip("/") for item in JWT_NOTIFICATION_PATHS} or normalized.startswith(
        "/api/notifications/"
    ):
        if normalized.endswith("/stream") or normalized.endswith("/stream/"):
            return should_open_stream(session, bearer_token=bearer_token)
        return should_fetch(session, bearer_token=bearer_token)
    return True


def policy_payload(session: Session | None, *, bearer_token: str | None = None) -> dict[str, object]:
    hints = transport_hints(session, bearer_token=bearer_token)
    jwt_ok = requires_bearer_token(session) or bool(bearer_token)
    return {
        **hints,
        "fetch_notifications_http": jwt_ok,
        "open_notification_stream": jwt_ok,
        "use_console_inbox": should_use_console_inbox(session, bearer_token=bearer_token),
        "reason": "demo_or_guest" if is_demo_or_guest(session) else ("bearer" if jwt_ok else "anonymous"),
    }
