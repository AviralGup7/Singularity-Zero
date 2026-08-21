"""Parse Retry-After from HTTP headers, exceptions, or tool stderr."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

_RETRY_AFTER_RE = re.compile(
    r"retry-after\s*[:=]\s*(\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
_MAX_RETRY_AFTER_SECONDS = 300.0


def _from_numeric(value: object) -> float | None:
    try:
        seconds = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if seconds < 0:
        return None
    return min(seconds, _MAX_RETRY_AFTER_SECONDS)


def _from_http_date(value: str) -> float | None:
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    delta = (when - datetime.now(UTC)).total_seconds()
    if delta < 0:
        return 0.0
    return min(delta, _MAX_RETRY_AFTER_SECONDS)


def parse_retry_after_header(value: object) -> float | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    numeric = _from_numeric(raw)
    if numeric is not None:
        return numeric
    return _from_http_date(raw)


def parse_retry_after_text(text: object) -> float | None:
    blob = str(text or "")
    match = _RETRY_AFTER_RE.search(blob)
    if not match:
        return None
    return _from_numeric(match.group(1))


def _headers_from(source: object) -> dict[str, object]:
    headers = getattr(source, "headers", None)
    if isinstance(headers, dict):
        return headers
    response = getattr(source, "response", None)
    response_headers = getattr(response, "headers", None)
    if isinstance(response_headers, dict):
        return response_headers
    return {}


def parse_retry_after(source: object) -> float | None:
    """Best-effort Retry-After extraction from an exception, headers, or text."""
    if source is None:
        return None
    direct = getattr(source, "retry_after", None)
    parsed = parse_retry_after_header(direct) if direct is not None else None
    if parsed is not None:
        return parsed
    headers = _headers_from(source)
    for key, value in headers.items():
        if str(key).lower() == "retry-after":
            parsed = parse_retry_after_header(value)
            if parsed is not None:
                return parsed
    parsed = parse_retry_after_text(source)
    if parsed is not None:
        return parsed
    return parse_retry_after_text(getattr(source, "args", None))


def override_backoff(computed_backoff: float, source: object) -> float:
    """Prefer a server Retry-After when present; otherwise keep computed delay."""
    parsed = parse_retry_after(source)
    if parsed is None:
        return max(0.0, float(computed_backoff))
    return parsed
