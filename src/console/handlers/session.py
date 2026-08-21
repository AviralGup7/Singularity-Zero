"""Session and handshake handlers."""

from __future__ import annotations

from typing import Any

from src.auth.demo import demo_card
from src.auth.sessions import describe
from src.console.context import RequestContext
from src.console.demo_channel import policy_payload
from src.integration.authz import transport_hints
from src.integration.commands import catalog_payload
from src.integration.errors import not_found, unauthorized
from src.integration.handshake import HandshakeOffer, accept
from src.integration.health import ping_payload
from src.integration.protocol import PROTOCOL_VERSION


def handle_handshake_open(ctx: RequestContext) -> dict[str, Any]:
    offer = HandshakeOffer.from_payload(ctx.payload)
    if offer.kind == "guest":
        session = ctx.runtime.sessions.issue_guest()
    elif offer.kind in {"jwt", "api_key"}:
        # JWT issuance stays in the dashboard. The bridge only accepts an
        # already-issued bearer on later calls.
        session = ctx.runtime.sessions.issue_demo(offer.name, offer.role)
    else:
        session = ctx.runtime.sessions.issue_demo(offer.name, offer.role)
    conn = ctx.extras["connections"].open(
        subject=session.subject,
        protocol=PROTOCOL_VERSION,
        kind=session.kind.value,
        now=ctx.now,
    )
    accepted = accept(offer)
    return {
        **accepted,
        "connection_id": conn.connection_id,
        "session": describe(session),
        "catalog": catalog_payload(capabilities=session.capabilities),
        "transport": transport_hints(session, bearer_token=session.bearer_token),
        "notifications_policy": policy_payload(session, bearer_token=session.bearer_token),
    }


def handle_handshake_ping(ctx: RequestContext) -> dict[str, Any]:
    connections = ctx.extras["connections"]
    connections.touch(ctx.envelope.connection_id, now=ctx.now)
    return ping_payload(
        connections=len(connections),
        sessions=len(ctx.runtime.sessions),
        jobs=len(ctx.runtime.store),
    )


def handle_handshake_close(ctx: RequestContext) -> dict[str, Any]:
    closed = ctx.extras["connections"].close(ctx.envelope.connection_id or "")
    return {"closed": closed}


def handle_demo_sign_in(ctx: RequestContext) -> dict[str, Any]:
    name = str(ctx.payload.get("name") or ctx.payload.get("subject") or "Demo Analyst")
    role = str(ctx.payload.get("role") or "analyst")
    session = ctx.runtime.sessions.issue_demo(name, role)
    conn = ctx.extras["connections"].open(
        subject=session.subject,
        protocol=PROTOCOL_VERSION,
        kind=session.kind.value,
        now=ctx.now,
    )
    return {
        "session": demo_card(session),
        "connection_id": conn.connection_id,
        "catalog": catalog_payload(capabilities=session.capabilities),
        "notifications_policy": policy_payload(session),
    }


def handle_session_describe(ctx: RequestContext) -> dict[str, Any]:
    if ctx.session is None:
        raise unauthorized()
    return {
        "session": describe(ctx.session),
        "notifications_policy": policy_payload(ctx.session, bearer_token=ctx.envelope.bearer_token),
    }


def handle_session_revoke(ctx: RequestContext) -> dict[str, Any]:
    if ctx.session is None:
        raise unauthorized()
    removed = ctx.runtime.sessions.revoke(ctx.session.subject)
    if ctx.envelope.connection_id:
        ctx.extras["connections"].close(ctx.envelope.connection_id)
    if not removed:
        raise not_found("session not found", subject=ctx.session.subject)
    return {"revoked": True, "subject": ctx.session.subject}
