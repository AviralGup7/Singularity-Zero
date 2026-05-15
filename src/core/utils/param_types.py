"""Parameter type constants and decoding utilities for the core layer.

This module provides the canonical definitions of parameter name sets
and the value-decoding helper used across mutation, analysis, and
execution layers.  All other packages should import from here (or
from a package that re-exports these names) to avoid cross-layer
dependencies.
"""

import re
from urllib.parse import unquote

__all__ = [
    "REDIRECT_PARAM_NAMES",
    "IDOR_PARAM_NAMES",
    "SSRF_PARAM_NAMES",
    "TOKEN_PARAM_NAMES",
    "UUID_RE",
    "decode_candidate_value",
]

# ---------------------------------------------------------------------------
# Parameter name sets
# ---------------------------------------------------------------------------

REDIRECT_PARAM_NAMES: set[str] = {
    "callback",
    "continue",
    "dest",
    "destination",
    "next",
    "redirect",
    "redirect_to",
    "return",
    "return_to",
    "target",
    "url",
}

IDOR_PARAM_NAMES: set[str] = {
    "account",
    "account_id",
    "customer",
    "customer_id",
    "doc",
    "document",
    "document_id",
    "file",
    "group",
    "group_id",
    "id",
    "invoice",
    "invoice_id",
    "member",
    "member_id",
    "object",
    "object_id",
    "order",
    "order_id",
    "org",
    "org_id",
    "profile",
    "project",
    "project_id",
    "record",
    "record_id",
    "tenant",
    "tenant_id",
    "user",
    "user_id",
    "uuid",
}

SSRF_PARAM_NAMES: set[str] = {
    "callback",
    "continue",
    "data",
    "dest",
    "destination",
    "domain",
    "feed",
    "file",
    "host",
    "image",
    "load",
    "next",
    "path",
    "proxy",
    "redirect",
    "remote_auth_id",
    "reference",
    "resource",
    "return",
    "return_to",
    "site",
    "state",
    "target",
    "uri",
    "url",
    "validate",
    "webhook",
    "profile",
    "endpoint",
    "fetch",
    "forward",
    "go",
    "href",
    "html",
    "link",
    "location",
    "lookup",
    "nav",
    "open",
    "out",
    "page",
    "portal",
    "ref",
    "request_uri",
    "server",
    "show",
    "source",
    "to",
    "view",
    "window",
}

TOKEN_PARAM_NAMES: set[str] = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "bearer",
    "code",
    "id_token",
    "jwt",
    "refresh_token",
    "session",
    "sessionid",
    "token",
}

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def decode_candidate_value(value: str, max_rounds: int = 3) -> str:
    """URL-decode a value iteratively to handle double/triple encoding."""
    decoded = str(value or "").strip()
    for _ in range(max_rounds):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded.strip()
