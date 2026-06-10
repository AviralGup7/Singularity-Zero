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

AUTH_HEADER_ALIASES: dict[str, str] = {}
for _h in AUTH_HEADERS:
    AUTH_HEADER_ALIASES[_h.lower()] = _h


def _get_header(headers: dict[str, Any], header_name: str) -> Any:
    lower_key = header_name.lower()
    for key, value in headers.items():
        if key.lower() == lower_key:
            return value
    return None


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
    "cookie_modified_accepted": 0.72,
    "cookie_deleted_auth_still_valid": 0.76,
    "param_bypass_admin_true": 0.80,
    "param_bypass_role_admin": 0.85,
    "param_bypass_role_administrator": 0.85,
    "param_bypass_debug": 0.65,
    "param_bypass_debug_true": 0.65,
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
    "cookie_modified_accepted": "medium",
    "cookie_deleted_auth_still_valid": "high",
    "param_bypass_admin_true": "high",
    "param_bypass_role_admin": "critical",
    "param_bypass_role_administrator": "critical",
    "param_bypass_debug": "medium",
    "param_bypass_debug_true": "medium",
    "param_bypass_token_null": "high",
    "param_bypass_accepted": "high",
    "param_body_bypass": "critical",
}


def _normalize_issue_key(issue_key: str) -> str:
    key = issue_key.lower()
    replacements = {
        "param_bypass_role_administrator": "param_bypass_role_admin",
        "param_bypass_debug_true": "param_bypass_debug",
        "param_bypass_debug_1": "param_bypass_debug",
        "param_bypass_admin_1": "param_bypass_admin_true",
        "param_bypass_admin_yes": "param_bypass_admin_true",
        "param_bypass_isadmin_true": "param_bypass_admin_true",
    }
    return replacements.get(key, key)


def probe_confidence_from_auth_bypass_map(
    issues: list[str],
    default: float = 0.5,
    cap: float = 0.98,
) -> float:
    if not issues:
        return default
    normalized = [_normalize_issue_key(issue) for issue in issues]
    max_conf = max(AUTH_BYPASS_CONFIDENCE.get(issue, default) for issue in normalized)
    bonus = min(0.06, len(issues) * 0.02)
    return round(min(max_conf + bonus, cap), 2)


def probe_severity_from_auth_bypass_map(
    issues: list[str],
    default: str = "low",
) -> str:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    if not issues:
        return default
    normalized = [_normalize_issue_key(issue) for issue in issues]
    valid_severities = [
        AUTH_BYPASS_SEVERITY.get(issue) for issue in normalized if issue in AUTH_BYPASS_SEVERITY
    ]
    if not valid_severities:
        return default
    return min(valid_severities, key=lambda s: severity_order.get(s, 3))


def _has_auth_indicator(headers: dict[str, Any], body: str) -> bool:
    for header_name in AUTH_HEADERS:
        if _get_header(headers, header_name):
            return True
    body_lower = body.lower()
    return any(t in body_lower for t in ("authenticated", "authenticated_user", "token_valid"))


def _extract_jwt_from_headers(headers: dict[str, Any]) -> str | None:
    for header_name in AUTH_HEADERS:
        val = _get_header(headers, header_name)
        if val and isinstance(val, str):
            if val.startswith("Bearer "):
                val = val[7:]
            match = JWT_RE.match(val)
            if match:
                return cast(str, val)
    return None


def _to_str_body(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return ""
    return str(value)
