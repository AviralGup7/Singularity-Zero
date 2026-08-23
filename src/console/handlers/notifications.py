"""Inbox handlers that work for demo sessions without a JWT."""

from __future__ import annotations

from typing import Any

from src.console.context import RequestContext
from src.console.demo_channel import policy_payload
from src.console.views import notification_card
from src.integration.errors import bad_request, not_found
from src.notifications.metrics import inbox_stats


def handle_policy(ctx: RequestContext) -> dict[str, Any]:
    return policy_payload(ctx.session, bearer_token=ctx.envelope.bearer_token)


def handle_list(ctx: RequestContext) -> dict[str, Any]:
    unread_only = str(
        ctx.query.get("unread_only") or ctx.payload.get("unread_only") or ""
    ).lower() in {
        "1",
        "true",
        "yes",
    }
    limit = int(ctx.query.get("limit") or ctx.payload.get("limit") or 100)
    offset = int(ctx.query.get("offset") or ctx.payload.get("offset") or 0)
    items = ctx.runtime.inbox.list(unread_only=unread_only, limit=limit, offset=offset)
    stats = inbox_stats(ctx.runtime.inbox)
    return {
        "notifications": [notification_card(item) for item in items],
        "unread_count": ctx.runtime.inbox.unread_count(),
        "total": stats["total"],
        "limit": limit,
        "offset": offset,
        "critical": stats["critical"],
        "high": stats["high"],
        "source": "console",
    }


def handle_mark_read(ctx: RequestContext) -> dict[str, Any]:
    notification_id = ctx.param("id")
    if not notification_id:
        raise bad_request("notification id required")
    if not ctx.runtime.inbox.mark_read(notification_id):
        raise not_found("notification not found", id=notification_id)
    return {"id": notification_id, "read": True, "unread_count": ctx.runtime.inbox.unread_count()}


def handle_mark_all(ctx: RequestContext) -> dict[str, Any]:
    changed = ctx.runtime.inbox.mark_all_read()
    return {"changed": changed, "unread_count": 0}


def handle_delete(ctx: RequestContext) -> dict[str, Any]:
    notification_id = ctx.param("id")
    if not notification_id:
        raise bad_request("notification id required")
    if not ctx.runtime.inbox.delete(notification_id):
        raise not_found("notification not found", id=notification_id)
    return {
        "id": notification_id,
        "deleted": True,
        "unread_count": ctx.runtime.inbox.unread_count(),
    }
