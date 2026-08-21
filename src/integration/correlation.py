"""Request correlation identifiers used on every bridge hop."""

from __future__ import annotations

import re
import uuid

_REQUEST_RE = re.compile(r"^[A-Za-z0-9._:-]{6,80}$")


def new_request_id() -> str:
    return f"req-{uuid.uuid4().hex[:20]}"


def new_connection_id() -> str:
    return f"con-{uuid.uuid4().hex[:16]}"


def new_event_id() -> str:
    return f"evt-{uuid.uuid4().hex[:16]}"


def normalize_request_id(value: object) -> str:
    raw = str(value or "").strip()
    if _REQUEST_RE.match(raw):
        return raw
    return new_request_id()


def normalize_connection_id(value: object) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.startswith("con-") and _REQUEST_RE.match(raw):
        return raw
    return None
