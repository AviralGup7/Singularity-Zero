"""Wire protocol constants shared by the console gateway and the UI client."""

from __future__ import annotations

PROTOCOL_NAME = "security-console-bridge"
PROTOCOL_VERSION = "1.0"
PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 0
MEDIA_TYPE = "application/vnd.security-console.bridge+json"
CLIENT_NAME = "security-console"
HTTP_PREFIX = "/api/console"
REQUEST_ID_HEADER = "X-Request-ID"
CONNECTION_HEADER = "X-Console-Connection"
SUBJECT_HEADER = "X-Console-Subject"
IDEMPOTENCY_HEADER = "Idempotency-Key"
PROTOCOL_HEADER = "X-Console-Protocol"
SESSION_KIND_HEADER = "X-Console-Session-Kind"


def protocol_compatible(client_version: str) -> bool:
    raw = str(client_version or "").strip()
    if not raw:
        return False
    major_s, _, minor_s = raw.partition(".")
    try:
        major = int(major_s)
    except ValueError:
        return False
    if major != PROTOCOL_MAJOR:
        return False
    if not minor_s:
        return True
    try:
        int(minor_s.split(".", 1)[0])
    except ValueError:
        return False
    return True


def encode_protocol() -> str:
    return f"{PROTOCOL_MAJOR}.{PROTOCOL_MINOR}"
