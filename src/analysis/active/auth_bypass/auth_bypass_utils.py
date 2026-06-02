"""Shared utilities for auth bypass probes."""

import logging
import re
from typing import Any, cast

logger = logging.getLogger(__name__)

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

AUTH_HEADERS = [
    "Authorization",
    "X-Access-Token",
    "X-Auth-Token",
    "X-JWT-Token",
    "X-Api-Token",
    "X-Auth",
    "X-Api-Key",
]

AUTH_BYPASS_PARAMS = {
    "admin": ["true", "1", "yes", "True"],
    "role": ["admin", "administrator", "superuser", "root"],
    "is_admin": ["true", "1", "yes"],
    "user_role": ["admin", "superadmin"],
    "access_level": ["admin", "999", "unlimited"],
    "privilege": ["admin", "elevated", "root"],
    "bypass": ["1", "true", "yes"],
    "debug": ["true", "1"],
    "test": ["true", "1"],
    "token": ["null", "undefined", "none", ""],
    "auth": ["none", "null", "bypass"],
    "authenticated": ["true", "1"],
    "authorized": ["true", "1"],
    "scope": ["admin", "superuser", "*"],
    "permissions": ["admin", "all", "*"],
}

AUTH_BYPASS_CONFIDENCE = {
    "jwt_stripping_bypass": 0.90,
    "jwt_stripping_partial_access": 0.75,
    "cookie_empty_bypass": 0.85,
    "cookie_deleted_bypass": 0.88,
    "cookie_modified_bypass": 0.82,
    "cookie_fixation_indicator": 0.70,
    "param_bypass_admin_true": 0.80,
    "param_bypass_role_admin": 0.85,
    "param_bypass_debug": 0.65,
    "param_bypass_token_null": 0.78,
    "param_bypass_accepted": 0.82,
    "param_body_bypass": 0.84,
}

AUTH_BYPASS_SEVERITY = {
    "jwt_stripping_bypass": "critical",
    "jwt_stripping_partial_access": "high",
    "cookie_empty_bypass": "critical",
    "cookie_deleted_bypass": "critical",
    "cookie_modified_bypass": "high",
    "cookie_fixation_indicator": "medium",
    "param_bypass_admin_true": "high",
    "param_bypass_role_admin": "critical",
    "param_bypass_debug": "medium",
    "param_bypass_token_null": "high",
    "param_bypass_accepted": "high",
    "param_body_bypass": "critical",
}


def _has_auth_indicator(headers: dict[str, Any], body: str) -> bool:
    for hdr in AUTH_HEADERS:
        if headers.get(hdr) or headers.get(hdr.lower()):
            return True
    body_lower = body.lower()
    return any(t in body_lower for t in ("authenticated", "authenticated_user", "token_valid"))


def _extract_jwt_from_headers(headers: dict[str, Any]) -> str | None:
    for header_name in AUTH_HEADERS:
        val = headers.get(header_name) or headers.get(header_name.lower())
        if val and isinstance(val, str):
            if val.startswith("Bearer "):
                val = val[7:]
            match = JWT_RE.match(val)
            if match:
                return cast(str, val)
    return None
