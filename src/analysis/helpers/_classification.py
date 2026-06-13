"""Endpoint classification and URL analysis utilities."""

from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

from src.core.utils.endpoint_classification import (
    API_PATH_HINTS as API_PATH_HINTS,
    AUTH_PATH_HINTS as AUTH_PATH_HINTS,
    BACKUP_PATH_HINTS as BACKUP_PATH_HINTS,
    DEBUG_PATH_HINTS as DEBUG_PATH_HINTS,
    EXPOSED_PATH_HINTS as EXPOSED_PATH_HINTS,
    LOW_VALUE_ENDPOINT_TYPES as LOW_VALUE_ENDPOINT_TYPES,
    REDIRECT_PATH_HINTS as REDIRECT_PATH_HINTS,
    STATIC_PATH_HINTS as STATIC_PATH_HINTS,
    THIRD_PARTY_AUTH_HOSTS as THIRD_PARTY_AUTH_HOSTS,
    TRACKING_PARAM_NAMES as TRACKING_PARAM_NAMES,
    TRACKING_PARAM_PREFIXES as TRACKING_PARAM_PREFIXES,
    classify_endpoint as classify_endpoint,
    endpoint_base_key as endpoint_base_key,
    endpoint_signature as endpoint_signature,
    extract_host_candidate as extract_host_candidate,
    filter_noise_urls as filter_noise_urls,
    has_meaningful_parameters as has_meaningful_parameters,
    is_auth_flow_endpoint as is_auth_flow_endpoint,
    is_low_value_endpoint as is_low_value_endpoint,
    is_noise_url as is_noise_url,
    is_suspicious_path_redirect as is_suspicious_path_redirect,
    is_third_party_auth_host as is_third_party_auth_host,
    is_tracking_param as is_tracking_param,
    meaningful_query_pairs as meaningful_query_pairs,
    same_host_family as same_host_family,
    strip_tracking_params as strip_tracking_params,
)
from src.core.utils.param_types import decode_candidate_value


@lru_cache(maxsize=4096)
def is_self_endpoint(url: str) -> bool:
    """Check if a URL targets the current user's own resource (/me, /users/me)."""
    path = urlparse(url).path.lower()
    segments = [seg for seg in path.split("/") if seg]
    if not segments:
        return False
    self_tokens = ("me", "my", "self", "current")
    for seg in segments:
        if seg in self_tokens:
            return True
        for tok in self_tokens:
            if seg == f"users.{tok}":
                return True
    if len(segments) >= 1:
        last = segments[-1]
        if last in {"account", "profile", "me", "my", "self", "current"}:
            return True
    return False


@lru_cache(maxsize=4096)
def is_debug_endpoint(url: str) -> bool:
    """Check if a URL is a debug/info endpoint (actuator, env, metrics, etc.)."""
    lowered = urlparse(url).path.lower()
    return any(token in lowered for token in DEBUG_PATH_HINTS)


@lru_cache(maxsize=4096)
def is_backup_endpoint(url: str) -> bool:
    """Check if a URL points to a backup/config file."""
    lowered = urlparse(url).path.lower()
    return any(lowered.endswith(token) or token in lowered for token in BACKUP_PATH_HINTS)


@lru_cache(maxsize=4096)
def is_exposed_spec_endpoint(url: str) -> bool:
    """Check if a URL exposes API specifications (OpenAPI/Swagger/GraphQL introspection)."""
    lowered = urlparse(url).path.lower()
    return any(token in lowered for token in EXPOSED_PATH_HINTS)


def build_endpoint_meta(url: str) -> dict[str, str]:
    """Build a dict with endpoint_key, endpoint_base_key, and endpoint_type."""
    return {
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
    }


def resolve_endpoint_key(item: dict[str, Any], fallback_url: str = "") -> str:
    """Resolve a canonical endpoint key from a finding or analysis item."""
    return str(
        item.get("endpoint_key")
        or item.get("endpoint_base_key")
        or fallback_url
        or item.get("url", "")
    )


def ensure_endpoint_key(item: dict[str, Any], url: str) -> str:
    """Ensure an endpoint key is available, computing from URL if needed."""
    return str(item.get("endpoint_key") or endpoint_signature(url))
