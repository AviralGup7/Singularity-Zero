"""Token analysis and host/URL utilities for the core layer.

Provides token shape detection, replay likelihood estimation, host extraction,
internal host detection, and DNS callback detection. Used by both analysis and
execution packages without cross-layer dependencies.
"""

from typing import Any
from urllib.parse import urlparse

from src.core.utils.param_types import decode_candidate_value

# ---------------------------------------------------------------------------
# Regex patterns (duplicated here for zero-dependency import)
# ---------------------------------------------------------------------------

import re

JWT_LIKE_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
EMAIL_VALUE_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
DNS_LIKE_RE = re.compile(r"^(?:[a-z0-9-]+\.){2,}[a-z]{2,}(?::\d{1,5})?$", re.IGNORECASE)
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
API_KEY_RE = re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b")
GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{24,}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")
STRIPE_KEY_RE = re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")
LONG_ALNUM_RE = re.compile(r"\b[A-Za-z0-9]{32,}\b")
HEX_ONLY_RE = re.compile(r"^[a-f0-9]{32,}$", re.IGNORECASE)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
IP_RE = re.compile(r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|169\.254\.)")

HIGH_RISK_LOCATION_ORDER = {
    "response_body": 0,
    "referer_risk": 1,
    "header": 2,
    "query_parameter": 3,
    "unknown": 4,
}

LOCATION_SEVERITY = {
    "response_body": "high",
    "referer_risk": "high",
    "header": "medium",
    "query_parameter": "medium",
    "unknown": "low",
}


def token_shape(value: str) -> str:
    """Identify the shape/type of a token value."""
    decoded = decode_candidate_value(value)
    if JWT_LIKE_RE.search(decoded):
        return "jwt_like"
    if decoded.lower().startswith("bearer "):
        return "bearer_token"
    if AWS_KEY_RE.search(decoded):
        return "aws_access_key"
    if API_KEY_RE.search(decoded):
        return "api_key"
    if GITHUB_TOKEN_RE.search(decoded):
        return "github_token"
    if SLACK_TOKEN_RE.search(decoded):
        return "slack_token"
    if STRIPE_KEY_RE.search(decoded):
        return "stripe_key"
    if LONG_ALNUM_RE.search(decoded) and len(decoded) >= 32:
        return "session_id"
    if HEX_ONLY_RE.search(decoded):
        return "hex_token"
    if len(decoded) <= 12 and decoded.isalnum():
        return "oauth_code"
    return "generic"


def replay_likelihood(location: str, token_shapes: list[str], repeat_count: int) -> float:
    """Estimate the likelihood that a token can be replayed."""
    base = 0.35
    if str(location).lower() == "response_body":
        base += 0.3
    elif str(location).lower() == "referer_risk":
        base += 0.18
    if "jwt_like" in token_shapes:
        base += 0.15
    if repeat_count >= 2:
        base += min(0.18, repeat_count * 0.04)
    return round(min(base, 0.98), 2)


def token_location_severity(location: str) -> str:
    """Return severity level for a token location."""
    return LOCATION_SEVERITY.get(str(location or "").strip().lower(), "low")


def sort_token_targets(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort token targets by risk location, leak count, and URL."""
    return sorted(
        items,
        key=lambda item: (
            HIGH_RISK_LOCATION_ORDER.get(str(item.get("location", "unknown")).lower(), 9),
            -int(item.get("leak_count", 1)),
            item.get("url", ""),
        ),
    )


def extract_host_candidate(value: str) -> str:
    """Extract a host candidate from a potentially encoded value."""
    decoded = decode_candidate_value(value)
    if not decoded:
        return ""
    if decoded.startswith("//"):
        parsed = urlparse(f"https:{decoded}")
        return parsed.netloc.lower()
    if "://" in decoded:
        return urlparse(decoded).netloc.lower()
    if DNS_LIKE_RE.match(decoded):
        return decoded.lower()
    return ""


def is_dangerous_scheme(value: str) -> bool:
    """Check if a value starts with a dangerous URI scheme."""
    decoded = decode_candidate_value(value).lower()
    return decoded.startswith(("file://", "ftp://", "gopher://"))


def has_remote_scheme(value: str) -> bool:
    """Check if a value starts with a remote URI scheme."""
    decoded = decode_candidate_value(value).lower()
    return decoded.startswith(("http://", "https://", "ftp://", "gopher://", "file://"))


def is_internal_host_value(value: str) -> bool:
    """Check if a value references an internal/private network host."""
    lowered = decode_candidate_value(value).lower()
    host = extract_host_candidate(lowered) or lowered

    standard_tokens = (
        "127.0.0.1",
        "169.254.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "192.168.",
        "10.",
        "localhost",
    )
    if any(token in host for token in standard_tokens):
        return True

    if host.startswith(("::1", "fe80:", "fc00:", "fd00:")):
        return True

    if any(
        token in host
        for token in (
            "169.254.169.254",
            "metadata.google",
            "metadata.azure",
            "100.100.100.200",
            "168.63.129.16",
        )
    ):
        return True

    if any(
        token in lowered
        for token in (
            "%31%32%37",
            "%31%30%30",
            "%31%39%32",
            "127%2e",
            "10%2e",
            "192%2e",
            "169%2e254",
        )
    ):
        return True

    if re.search(r"\b2130706433\b", lowered):
        return True
    if re.search(r"\b323223552[0-9]\b", lowered):
        return True

    if any(
        token in lowered
        for token in ("localhost", "localhost.localdomain", "0.0.0.0", "[::1]")  # nosec B104 # noqa: S104
    ):
        return True

    return False


def looks_like_dns_callback(value: str) -> bool:
    """Check if a value looks like a DNS callback domain."""
    host = extract_host_candidate(value)
    if not host or is_internal_host_value(host):
        return False
    return bool(DNS_LIKE_RE.match(host)) and host.count(".") >= 2


def is_suspicious_path_redirect(value: str) -> bool:
    """Check if a value is a suspicious path-based redirect."""
    lowered = decode_candidate_value(value).lower()
    if not lowered.startswith(("/", "./", "../")):
        return False
    return any(
        token in lowered for token in ("/admin", "/api", "/debug", "/internal", "/oauth", "/token")
    )
