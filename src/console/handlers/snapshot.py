"""Operator snapshot + stream poll."""

from __future__ import annotations

from typing import Any

from src.console.context import RequestContext
from src.console.status import line, tones
from src.integration.events import StreamFrame


def handle_snapshot(ctx: RequestContext) -> dict[str, Any]:
    snap = ctx.runtime.snapshot(now=ctx.now)
    return {
        **snap,
        "line": line(ctx.runtime, now=ctx.now),
        "tones": tones(ctx.runtime, now=ctx.now),
    }


def handle_stream_poll(ctx: RequestContext) -> dict[str, Any]:
    connections = ctx.extras["connections"]
    conn = connections.touch(ctx.envelope.connection_id, now=ctx.now)
    after = str(ctx.query.get("after") or ctx.payload.get("after") or "") or None
    limit = int(ctx.query.get("limit") or ctx.payload.get("limit") or 50)
    if conn is None:
        return {"events": [StreamFrame.heartbeat().to_dict()], "connection": None}
    events = conn.poll(after_id=after, limit=limit)
    if not events:
        events = [StreamFrame.heartbeat().to_dict()]
    return {"events": events, "connection": conn.connection_id}
