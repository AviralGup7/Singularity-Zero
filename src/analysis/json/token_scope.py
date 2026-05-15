"""Token scope and referer propagation analysis for JSON responses.

Contains functions for analyzing token/scope field exposure in API responses
and tracking sensitive parameter propagation through referer headers.
Extracted from json_analysis.py for better separation of concerns.
"""

import base64
import json
import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    endpoint_base_key,
    endpoint_signature,
    meaningful_query_pairs,
)
from src.analysis.json.support import (
    SESSION_PARAM_NAMES,
)
from src.analysis.json.support import (
    parse_json_payload as _parse_json_payload,
)
from src.analysis.json.support import (
    summarize_json_payload as _summarize_json_payload,
)
from src.recon.common import normalize_url


def _extract_field_value(payload: dict[str, Any] | list[Any], field_path: str) -> Any | None:
    """Extract a value from a nested JSON payload by field path.

    Supports dot-notation paths like 'user.role' or 'data.scope'.
    """
    parts = field_path.split(".")
    current: object = payload
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and len(current) > 0:
            # Try first item in array
            current = current[0]
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        else:
            return None
    return current


def token_scope_analyzer(responses: list[dict[str, Any]], limit: int = 60) -> list[dict[str, Any]]:
    """Analyze JSON responses for token and scope field exposure.

    Detects OAuth scopes, role fields, permission grants, and admin hints
    in API responses. Enhanced with scope privilege scoring and dangerous
    permission detection.
    """
    # Dangerous OAuth scopes that indicate high privilege
    dangerous_scopes = {
        "admin",
        "superadmin",
        "root",
        "owner",
        "manage",
        "write",
        "delete",
        "full_access",
        "all",
        "sudo",
        "impersonate",
        "service_account",
    }
    # Scope values that indicate elevated privileges
    elevated_scope_values = {
        "read:all",
        "write:all",
        "admin:all",
        "user:write",
        "user:delete",
        "organization:admin",
        "account:admin",
        "tenant:admin",
    }

    findings: list[dict[str, Any]] = []
    for response in responses:
        payload = _parse_json_payload(response)
        if payload is None:
            continue
        summary = _summarize_json_payload(payload)
        fields = summary["field_names"]
        scope_like = sorted(
            field
            for field in fields
            if any(
                token in field
                for token in ("scope", "role", "permission", "access", "tenant", "admin")
            )
        )
        token_like = sorted(
            field for field in fields if "token" in field or field in {"jwt", "session"}
        )
        if not token_like and not scope_like:
            continue
        granted = sorted(set(scope_like + token_like))

        # Analyze scope values for privilege level
        scope_values = []
        privilege_score = 0
        dangerous_permissions = []
        for field in scope_like:
            # Check if field values contain dangerous scopes
            field_value = _extract_field_value(payload, field)
            if isinstance(field_value, str):
                scope_values.append(field_value)
                lowered = field_value.lower()
                if any(danger in lowered for danger in dangerous_scopes):
                    privilege_score += 3
                    dangerous_permissions.append(field)
                elif any(elevated in lowered for elevated in elevated_scope_values):
                    privilege_score += 2
                elif lowered in {"read", "view", "list"}:
                    privilege_score += 1  # Read-only is lower risk

        # Check for JWT algorithm hints
        jwt_alg_hint = ""
        for field in token_like:
            field_value = _extract_field_value(payload, field)
            if isinstance(field_value, str) and field_value.startswith("eyJ"):
                try:
                    header = field_value.split(".")[0]
                    # Add padding if needed
                    header += "=" * (4 - len(header) % 4)
                    decoded = base64.urlsafe_b64decode(header)
                    header_obj = json.loads(decoded)
                    jwt_alg_hint = str(header_obj.get("alg", ""))
                except Exception:  # noqa: BLE001
                    pass

        admin_scope_hint = any("admin" in field for field in granted) or privilege_score >= 3

        findings.append(
            {
                "url": str(response.get("url", "")).strip(),
                "endpoint_key": endpoint_signature(str(response.get("url", "")).strip()),
                "endpoint_base_key": endpoint_base_key(str(response.get("url", "")).strip()),
                "status_code": response.get("status_code"),
                "token_fields": token_like[:8],
                "granted_scope_fields": scope_like[:8],
                "granted_access_summary": granted[:10],
                "admin_scope_hint": admin_scope_hint,
                "scope_values": scope_values[:10],
                "privilege_score": privilege_score,
                "dangerous_permissions": dangerous_permissions[:5],
                "jwt_algorithm_hint": jwt_alg_hint,
                "signals": sorted(
                    {
                        "token_exposure",
                        "scope_exposure" if scope_like else "",
                        "admin_privilege" if admin_scope_hint else "",
                        "dangerous_scope" if dangerous_permissions else "",
                        "jwt_algorithm_exposed" if jwt_alg_hint else "",
                    }
                    - {""}
                ),
            }
        )
    findings.sort(
        key=lambda item: (
            not item["admin_scope_hint"],
            -item.get("privilege_score", 0),
            -len(item["granted_access_summary"]),
            item["url"],
        )
    )
    return findings[:limit]


def referer_propagation_tracking(
    urls: set[str], responses: list[dict[str, Any]], limit: int = 60
) -> list[dict[str, Any]]:
    """Track sensitive parameter propagation through referer headers."""
    findings: list[dict[str, Any]] = []
    response_by_url = {
        str(item.get("url", "")).strip(): item for item in responses if item.get("url")
    }
    for url in sorted(urls):
        query_pairs = meaningful_query_pairs(url)
        sensitive_params = [
            key
            for key, _ in query_pairs
            if key in SESSION_PARAM_NAMES or key in {"email", "user_id", "account_id"}
        ]
        if not sensitive_params:
            continue
        response = response_by_url.get(normalize_url(url))
        headers = {
            str(key).lower(): str(value)
            for key, value in (response or {}).get("headers", {}).items()
        }
        referrer_policy = headers.get("referrer-policy", "")
        external_links = []
        if response:
            for match in re.finditer(r"https?://[A-Za-z0-9._:-]+", response.get("body_text") or ""):
                host = urlparse(match.group(0)).netloc.lower()
                if host and host != urlparse(url).netloc.lower():
                    external_links.append(match.group(0))
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "sensitive_params": sorted(set(sensitive_params)),
                "referrer_policy": referrer_policy,
                "external_references": external_links[:6],
                "propagation_risk": bool(external_links)
                and referrer_policy.lower() not in {"no-referrer", "same-origin", "strict-origin"},
            }
        )
    findings.sort(
        key=lambda item: (not item["propagation_risk"], -len(item["sensitive_params"]), item["url"])
    )
    return findings[:limit]
