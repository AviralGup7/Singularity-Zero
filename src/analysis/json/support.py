"""JSON analysis support utilities for parsing and summarizing JSON payloads.

Provides functions for parsing JSON responses, summarizing payload structure,
detecting sensitive fields, and building URL mutations for JSON-based testing.
"""

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    JSON_CONTENT_TOKENS,
    classify_endpoint,
    json_type_name,
    meaningful_query_pairs,
)
from src.analysis.passive.patterns import UUID_RE
from src.analysis.text_utils import extract_key_fields
from src.analysis.json.mutations import (
    alternate_version_url,
    mutate_dependency_urls,
    mutate_error_probe_url,
    mutate_filter_url,
    mutate_pagination_url,
    mutate_role_url,
    mutate_state_url,
)

from ._constants import (
    AUTH_REQUIRED_FIELD_HINTS,
    DEPENDENCY_PARAM_NAMES,
    FILTER_MUTATIONS,
    PAGINATION_PARAM_NAMES,
    PUBLIC_AUTH_PAGE_HINTS,
    RESOURCE_SKIP_SEGMENTS,
    ROLE_MUTATION_PARAM_NAMES,
    SESSION_PARAM_NAMES,
    STATE_PARAM_NAMES,
    WRITE_PATH_HINTS,
)

ID_FIELD_RE = re.compile(
    r"(^id$|(^|_)(user|account|tenant|org|order|device|project|profile|member|customer|record|object|session)_id$|uuid$)"
)
ROLE_FIELD_TOKENS = (
    "role",
    "roles",
    "scope",
    "permission",
    "permissions",
    "tenant",
    "tenant_id",
    "account_id",
    "user_id",
    "is_admin",
    "is_superuser",
    "privileges",
    "access_level",
)
SENSITIVE_FIELD_TOKENS = (
    "email",
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "ssn",
    "authorization",
    "cookie",
    "phone",
    "mobile",
    "address",
    "dob",
    "birth_date",
    "date_of_birth",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "iban",
    "routing_number",
    "tax_id",
    "national_id",
    "passport",
    "license_number",
    "ip_address",
    "user_agent",
    "fingerprint",
    "device_id",
    "mac_address",
    "private_key",
    "access_key",
    "refresh_token",
    "session_id",
    "csrf_token",
    "xsrf_token",
    "hash",
    "salt",
    "encryption_key",
)
EMAIL_VALUE_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


def parse_json_payload(response: dict[str, Any]) -> dict[str, Any] | list[Any] | None:
    """Parse JSON body from an HTTP response dict.

    Args:
        response: Response dict with 'body_text' and 'content_type' keys.

    Returns:
        Parsed JSON object/list, or None if body is empty or not JSON.
    """
    body = response.get("body_text") or ""
    if not body:
        return None
    content_type = str(response.get("content_type", "")).lower()
    stripped = body.strip()
    if not any(token in content_type for token in JSON_CONTENT_TOKENS) and not stripped.startswith(
        ("{", "[")
    ):
        return None
    try:
        result = json.loads(stripped)
        if isinstance(result, (dict, list)):
            return result
        return None
    except (json.JSONDecodeError, ValueError) as exc:
        logger.debug("Failed to parse JSON payload: %s", exc)
        return None


def summarize_json_payload(payload: dict[str, Any] | list[Any]) -> dict[str, Any]:
    fields: dict[str, dict[str, Any]] = {}
    sensitive_fields: list[dict[str, Any]] = []
    id_fields: set[str] = set()
    nested_paths: list[str] = []
    top_level_keys: list[str] = sorted(payload.keys())[:20] if isinstance(payload, dict) else []
    metrics: dict[str, Any] = {
        "top_level_type": "object"
        if isinstance(payload, dict)
        else "array"
        if isinstance(payload, list)
        else "scalar",
        "top_level_keys": top_level_keys,
        "field_count": 0,
        "max_depth": 0,
        "object_count": 0,
        "array_count": 0,
        "field_names": set(),
        "fields": fields,
        "sensitive_fields": sensitive_fields,
        "id_fields": [],
        "nested_paths": nested_paths,
    }

    def walk(node: Any, path: str, depth: int) -> None:
        metrics["max_depth"] = max(metrics["max_depth"], depth)
        if isinstance(node, dict):
            metrics["object_count"] += 1
            for key, value in node.items():
                normalized_key = str(key).strip().lower()
                if not normalized_key:
                    continue
                current_path = f"{path}.{normalized_key}" if path else normalized_key
                metrics["field_count"] += 1
                metrics["field_names"].add(normalized_key)
                field_entry = fields.setdefault(
                    normalized_key, {"types": set(), "occurrences": 0, "paths": set()}
                )
                field_entry["occurrences"] += 1
                field_entry["types"].add(json_type_name(value))
                field_entry["paths"].add(current_path)
                if depth >= 1:
                    nested_paths.append(current_path)
                if ID_FIELD_RE.search(normalized_key):
                    id_fields.add(normalized_key)
                sensitivity = classify_sensitive_field(normalized_key, value)
                if sensitivity:
                    sensitive_fields.append(
                        {
                            "field": normalized_key,
                            "path": current_path,
                            "classification": sensitivity,
                        }
                    )
                walk(value, current_path, depth + 1)
            return
        if isinstance(node, list):
            metrics["array_count"] += 1
            for index, item in enumerate(node[:5]):
                walk(item, f"{path}[{index}]" if path else f"[{index}]", depth + 1)

    walk(payload, "", 0)
    metrics["id_fields"] = sorted(id_fields)
    metrics["nested_paths"] = sorted(set(nested_paths), key=lambda item: (item.count("."), item))[
        :24
    ]
    return metrics


def classify_sensitive_field(field_name: str, value: Any) -> str:
    lowered = field_name.lower()
    if "email" in lowered:
        return "email"
    if "ssn" in lowered:
        return "ssn"
    if "api_key" in lowered or "apikey" in lowered:
        return "api_key"
    if any(
        token in lowered for token in ("token", "secret", "password", "authorization", "cookie")
    ):
        return "credential"
    if isinstance(value, str):
        if EMAIL_VALUE_RE.search(value):
            return "email"
        if UUID_RE.search(value) and lowered.endswith("token"):
            return "credential"
    return ""


def resource_group_for_url(url: str) -> str:
    segments = [segment for segment in urlparse(url).path.lower().split("/") if segment]
    for segment in segments:
        if segment in RESOURCE_SKIP_SEGMENTS:
            continue
        if segment.isdigit() or UUID_RE.search(segment):
            continue
        return segment
    return ""


logger = logging.getLogger(__name__)

__all__ = [
    "access_boundary_state",
    "AUTH_REQUIRED_FIELD_HINTS",
    "classify_sensitive_field",
    "DEPENDENCY_PARAM_NAMES",
    "EMAIL_VALUE_RE",
    "FILTER_MUTATIONS",
    "find_related_authenticated_endpoints",
    "flow_stage_hint",
    "ID_FIELD_RE",
    "is_low_risk_read_candidate",
    "PAGINATION_PARAM_NAMES",
    "parse_json_payload",
    "PUBLIC_AUTH_PAGE_HINTS",
    "RESOURCE_SKIP_SEGMENTS",
    "resource_group_for_url",
    "response_has_auth_signals",
    "ROLE_FIELD_TOKENS",
    "ROLE_MUTATION_PARAM_NAMES",
    "SENSITIVE_FIELD_TOKENS",
    "SESSION_PARAM_NAMES",
    "STATE_PARAM_NAMES",
    "summarize_json_payload",
    "WRITE_PATH_HINTS",
]


def access_boundary_state(url: str, response: dict[str, Any]) -> str:
    query_keys = {key for key, _ in meaningful_query_pairs(url)}
    if (
        any(
            key in {"admin", "role", "roles", "scope", "permission", "permissions"}
            for key in query_keys
        )
        or "/admin" in url.lower()
    ):
        return "admin"
    status_code = int(response.get("status_code") or 0)
    body = (response.get("body_text") or "").lower()
    if status_code in {401, 403} or any(
        token in body for token in ("unauthorized", "forbidden", "signin required")
    ):
        return "private"
    if any(field in body for field in AUTH_REQUIRED_FIELD_HINTS):
        return "private"
    return "public"


def response_has_auth_signals(response: dict[str, Any]) -> bool:
    body = (response.get("body_text") or "").lower()
    if any(token in body for token in PUBLIC_AUTH_PAGE_HINTS):
        return False
    payload = parse_json_payload(response)
    if payload is not None:
        summary = summarize_json_payload(payload)
        fields = summary["field_names"]
        if fields & AUTH_REQUIRED_FIELD_HINTS:
            return True
        return len(fields & {"email", "name", "id", "account_id", "tenant_id"}) >= 2
    key_fields = extract_key_fields(body)
    if key_fields & AUTH_REQUIRED_FIELD_HINTS:
        return True
    return any(
        token in body for token in ("my account", "profile", "sign out", "logout", "billing")
    )


def is_low_risk_read_candidate(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if parsed.scheme not in {"http", "https"}:
        return False
    if classify_endpoint(url) in {"STATIC", "AUTH"}:
        return False
    if any(token in path for token in WRITE_PATH_HINTS):
        return False
    query_keys = {key for key, _ in meaningful_query_pairs(url)}
    if query_keys & SESSION_PARAM_NAMES:
        return False
    return True


def find_related_authenticated_endpoints(priority_urls: list[str], logout_url: str) -> list[str]:
    logout_host = urlparse(logout_url).netloc.lower()
    related = []
    for url in priority_urls:
        if url == logout_url or urlparse(url).netloc.lower() != logout_host:
            continue
        if any(
            token in url.lower()
            for token in ("/me", "/profile", "/account", "/settings", "/session")
        ):
            related.append(url)
    return related


def flow_stage_hint(url: str) -> int:
    lowered = str(url or "").lower()
    if any(token in lowered for token in ("/login", "/signin", "/auth")):
        return 1
    if "/oauth" in lowered:
        return 2
    if any(token in lowered for token in ("/callback", "/redirect", "/return")):
        return 3
    if any(token in lowered for token in ("/me", "/profile", "/account", "/dashboard")):
        return 4
    return 0
