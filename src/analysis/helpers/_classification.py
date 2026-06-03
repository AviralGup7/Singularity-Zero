"""Endpoint classification and URL analysis utilities."""

from functools import lru_cache
from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.core.utils.param_types import decode_candidate_value

from ._constants import (
    API_PATH_HINTS,
    AUTH_PATH_HINTS,
    BACKUP_PATH_HINTS,
    DEBUG_PATH_HINTS,
    EXPOSED_PATH_HINTS,
    LOW_VALUE_ENDPOINT_TYPES,
    REDIRECT_PATH_HINTS,
    STATIC_PATH_HINTS,
    THIRD_PARTY_AUTH_HOSTS,
    TRACKING_PARAM_NAMES,
    TRACKING_PARAM_PREFIXES,
)


@lru_cache(maxsize=2048)
def is_auth_flow_endpoint(url: str) -> bool:
    """Check if a URL is part of an authentication flow."""
    path = urlparse(url).path.lower()
    auth_flow_hints = {
        "login", "logout", "signin", "signout", "signup", "register",
        "auth", "oauth", "token", "refresh", "reset", "forgot",
        "password", "verify", "confirm", "activate", "deactivate",
        "session", "sso", "saml", "openid", "callback", "authorize",
        "consent", "challenge", "mfa", "totp", "webauthn", "passkey",
        "magic-link", "invite", "accept-invite", "recover", "unlock",
    }
    return any(hint in path for hint in auth_flow_hints)


@lru_cache(maxsize=4096)
def classify_endpoint(url: str) -> str:
    """Classify a URL by its endpoint type.

    Returns one of: STATIC, AUTH, REDIRECT, API, DEBUG, BACKUP, EXPOSED, GENERAL.
    """
    parsed = urlparse(url)
    lowered = parsed.path.lower()

    # Check for DEBUG endpoints first (more specific than API)
    if any(token in lowered for token in DEBUG_PATH_HINTS):
        return "DEBUG"

    # Check for BACKUP file endpoints
    if any(lowered.endswith(token) or token in lowered for token in BACKUP_PATH_HINTS):
        return "BACKUP"

    # Check for exposed docs/swagger endpoints
    if any(token in lowered for token in EXPOSED_PATH_HINTS):
        return "EXPOSED"

    if any(token in lowered for token in STATIC_PATH_HINTS):
        return "STATIC"
    if any(token in lowered for token in AUTH_PATH_HINTS):
        return "AUTH"
    if any(token in lowered for token in REDIRECT_PATH_HINTS):
        return "REDIRECT"
    if any(token in lowered for token in API_PATH_HINTS):
        return "API"
    return "GENERAL"


@lru_cache(maxsize=4096)
def is_low_value_endpoint(url: str) -> bool:
    """Check if a URL is a low-value endpoint (static, backup, help, etc.)."""
    endpoint_type = classify_endpoint(url)
    return endpoint_type in LOW_VALUE_ENDPOINT_TYPES


@lru_cache(maxsize=4096)
def is_self_endpoint(url: str) -> bool:
    """Check if a URL targets the current user's own resource (/me, /users/me)."""
    path = urlparse(url).path.lower()
    return any(
        path == token or path.endswith(token) or token in path
        for token in ("/me", "/users/me", "/users/me.json", "/account", "/profile", "/my", "/self", "/current")
    )


@lru_cache(maxsize=4096)
def is_debug_endpoint(url: str) -> bool:
    """Check if a URL is a debug/info endpoint (actuator, env, metrics, etc.)."""
    lowered = urlparse(url).path.lower()
    return any(token in lowered for token in DEBUG_PATH_HINTS)


@lru_cache(maxsize=4096)
def is_backup_endpoint(url: str) -> bool:
    """Check if a URL points to a backup/config file."""
    lowered = urlparse(url).path.lower()
    return any(
        lowered.endswith(token) or token in lowered
        for token in BACKUP_PATH_HINTS
    )


@lru_cache(maxsize=4096)
def is_exposed_spec_endpoint(url: str) -> bool:
    """Check if a URL exposes API specifications (OpenAPI/Swagger/GraphQL introspection)."""
    lowered = urlparse(url).path.lower()
    return any(token in lowered for token in EXPOSED_PATH_HINTS)


@lru_cache(maxsize=1024)
def is_tracking_param(name: str) -> bool:
    """Check if a parameter name is a known tracking/analytics parameter."""
    lowered = str(name or "").strip().lower()
    return lowered.startswith(TRACKING_PARAM_PREFIXES) or lowered in TRACKING_PARAM_NAMES


def meaningful_query_pairs(url: str) -> list[tuple[str, str]]:
    """Extract meaningful query parameters, filtering out tracking params."""
    pairs: list[tuple[str, str]] = []
    for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        normalized_key = key.strip().lower()
        if not normalized_key or is_tracking_param(normalized_key):
            continue
        pairs.append((normalized_key, decode_candidate_value(value)))
    return pairs


@lru_cache(maxsize=4096)
def has_meaningful_parameters(url: str) -> bool:
    """Check if a URL has any non-tracking query parameters."""
    return bool(meaningful_query_pairs(url))


def strip_tracking_params(url: str) -> list[tuple[str, str]]:
    """Extract query parameters excluding tracking/analytics params."""
    return meaningful_query_pairs(url)


@lru_cache(maxsize=4096)
def endpoint_signature(url: str, include_host: bool = False) -> str:
    """Build a canonical signature for a URL including path and query parameter names."""
    parsed = urlparse(url)
    keys = sorted({key for key, _ in meaningful_query_pairs(url)})
    host = parsed.netloc.lower() if include_host else ""
    return f"{host}|{parsed.path.lower()}|{'&'.join(keys)}"


@lru_cache(maxsize=4096)
def endpoint_base_key(url: str, include_host: bool = False) -> str:
    """Build a base key for a URL (host + path only, no query params)."""
    parsed = urlparse(url)
    host = parsed.netloc.lower() if include_host else ""
    return f"{host}|{parsed.path.lower()}"


def is_noise_url(url: str) -> bool:
    """Check if a URL is likely noise (static assets, third-party trackers, etc.)."""
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    if is_third_party_auth_host(host):
        return True
    if any(token in path for token in STATIC_PATH_HINTS):
        return True
    if any(token in path or path.endswith(token) for token in BACKUP_PATH_HINTS):
        return True
    if host.startswith(("static.", "cdn.", "img.", "images.")):
        return True
    if "facebook.com" in host or "fbcdn.net" in host:
        return True
    return False


def same_host_family(left: str, right: str) -> bool:
    """Check if two hosts belong to the same family (support multi-part TLDs)."""
    left_labels = [part for part in left.lower().split(".") if part]
    right_labels = [part for part in right.lower().split(".") if part]
    if not left_labels or not right_labels:
        return False

    common_slds = {"co", "com", "org", "gov", "edu", "net", "mil", "asn", "id", "ltd", "me", "plc", "sch"}

    def get_family_slice(labels: list[str]) -> list[str]:
        if len(labels) >= 3:
            tld = labels[-1]
            sld = labels[-2]
            if len(tld) == 2 and sld in common_slds:
                return labels[-3:]
        return labels[-2:]

    return get_family_slice(left_labels) == get_family_slice(right_labels)


def is_third_party_auth_host(host: str, target_host: str = "") -> bool:
    """Check if a host is a third-party authentication provider."""
    lowered = str(host or "").lower()
    if target_host and same_host_family(lowered, target_host.lower()):
        return False
    return any(
        lowered == domain or lowered.endswith(f".{domain}")
        for domain in THIRD_PARTY_AUTH_HOSTS
    )


def filter_noise_urls(urls: set[str]) -> list[str]:
    """Filter out noise URLs and return sorted list of meaningful URLs."""
    return [raw_url for raw_url in sorted(urls) if not is_noise_url(raw_url)]


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
