"""Bridge health used by handshake.ping."""

from __future__ import annotations

from typing import Any

from src.integration.protocol import PROTOCOL_NAME, PROTOCOL_VERSION


def ping_payload(*, connections: int, sessions: int, jobs: int) -> dict[str, Any]:
    return {
        "ok": True,
        "protocol": PROTOCOL_VERSION,
        "protocol_name": PROTOCOL_NAME,
        "connections": int(connections),
        "sessions": int(sessions),
        "jobs": int(jobs),
    }
