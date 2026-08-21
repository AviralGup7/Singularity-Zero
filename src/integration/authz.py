"""Capability gates for bridge commands."""

from __future__ import annotations

from src.auth.policy import is_demo_or_guest, requires_bearer_token
from src.auth.rbac import can_launch, can_stop
from src.auth.session import Session
from src.integration.commands import AuthMode, CommandSpec
from src.integration.errors import forbidden, unauthorized


def resolve_allowed(session: Session | None, spec: CommandSpec) -> None:
    if spec.auth is AuthMode.PUBLIC:
        return
    if session is None:
        raise unauthorized("sign in required")
    if spec.auth is AuthMode.BEARER:
        if not requires_bearer_token(session):
            raise forbidden(
                "bearer token required",
                kind=session.kind.value,
                command=spec.key,
            )
    if spec.auth is AuthMode.SESSION and is_demo_or_guest(session):
        # Demo and guest may use the console channel; they just cannot
        # pretend to be a JWT session.
        pass
    if spec.capability:
        if session.allows(spec.capability):
            return
        if spec.capability == "launchJobs" and can_launch(session):
            return
        if spec.capability == "stopJobs" and can_stop(session):
            return
        raise forbidden(
            f"missing capability {spec.capability}",
            capability=spec.capability,
            role=session.role,
        )


def jwt_notifications_allowed(session: Session | None, *, bearer_token: str | None = None) -> bool:
    if bearer_token:
        return True
    return requires_bearer_token(session)


def transport_hints(session: Session | None, *, bearer_token: str | None = None) -> dict[str, bool]:
    jwt_ok = jwt_notifications_allowed(session, bearer_token=bearer_token)
    demo = is_demo_or_guest(session)
    return {
        "use_console_channel": True,
        "skip_jwt_notifications": not jwt_ok,
        "skip_jwt_notification_stream": not jwt_ok,
        "demo_or_guest": demo,
        "has_bearer_token": bool(bearer_token) or bool(session and session.has_bearer_token),
    }
