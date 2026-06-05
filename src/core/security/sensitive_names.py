"""Centralized names of HTTP request parameters, headers, and cookies that
must never be accepted as the primary auth path or echoed back in
responses / logs.

Historically three modules defined their own copy of this list and they
drifted apart — ``replay.py`` blocked ``password`` but not ``x-secret-key``,
``safe_errors.py`` did the opposite, and ``dependencies.py`` only checked
``token``.  This module is the single source of truth.

The names are case-insensitive.  They cover:

* Standard credential headers (Authorization, Cookie, X-API-Key, …)
* Common vendor extensions (X-Secret-Key, X-Access-Token, X-Auth-Token)
* Query-string tokens (token, password, secret, api_key)
"""

from __future__ import annotations

import re
from typing import Any, Final

SENSITIVE_HEADER_NAMES: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-secret-key",
        "x-access-token",
        "x-auth-token",
        "x-csrf-token",
        "proxy-authorization",
    }
)

SENSITIVE_QUERY_PARAMS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "cookie",
        "x-api-key",
        "x-secret-key",
        "x-access-token",
        "x-auth-token",
        "token",
        "password",
        "secret",
        "api_key",
        "apikey",
    }
)

SENSITIVE_BODY_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "auth_token",
        "refresh_token",
        "private_key",
    }
)

# Union for callers that want to check a single name regardless of where it
# appears in a request.
SENSITIVE_NAMES: Final[frozenset[str]] = (
    SENSITIVE_HEADER_NAMES | SENSITIVE_QUERY_PARAMS | SENSITIVE_BODY_FIELDS
)

# Pre-compiled regex for log/header scanning where we don't have a dict.
_SENSITIVE_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?:" + "|".join(re.escape(n) for n in sorted(SENSITIVE_NAMES)) + r")$",
    re.IGNORECASE,
)


def is_sensitive_name(name: str) -> bool:
    """Return True if ``name`` matches any sensitive parameter/header/field
    regardless of where it appears."""
    return bool(_SENSITIVE_NAME_PATTERN.match(name or ""))


def reject_if_query_contains_credentials(query_params: Any) -> list[str]:
    """Return the sorted list of credential-like query parameter names that
    appear in ``query_params`` (a ``Mapping[str, str]`` or any object
    supporting ``.keys()`` and ``.get()``).  Empty list means safe.

    The returned names preserve the original case from the input so the
    error message can be informative, but matching itself is
    case-insensitive.
    """
    leaked: list[str] = []
    keys = getattr(query_params, "keys", None)
    if keys is None:
        return leaked
    for name in keys():
        if is_sensitive_name(str(name)):
            leaked.append(str(name))
    return sorted(set(leaked), key=str.lower)
