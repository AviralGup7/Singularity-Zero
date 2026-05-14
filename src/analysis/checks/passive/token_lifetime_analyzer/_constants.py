"""Constants and regex patterns for token lifetime analysis."""

import re

__all__ = [
    "JWT_LIKE_RE",
    "SESSION_ID_RE",
    "API_KEY_RE",
    "OAUTH_TOKEN_RE",
    "TOKEN_IN_URL_RE",
    "SET_COOKIE_RE",
    "ALGORITHM_SECURITY",
    "THIRTY_DAYS_SECONDS",
    "TWENTY_FOUR_HOURS_SECONDS",
    "ONE_HOUR_SECONDS",
    "TOKEN_LIFETIME_ANALYZER_SPEC",
]

TOKEN_LIFETIME_ANALYZER_SPEC: dict[str, str | bool] = {
    "key": "token_lifetime_analyzer",
    "label": "Token Lifetime & Rotation Analyzer",
    "description": "Analyze authentication tokens for lifetime, rotation, algorithm, and exposure issues across responses.",
    "group": "passive",
    "slug": "token_lifetime",
    "enabled_by_default": True,
}

JWT_LIKE_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")

SESSION_ID_RE = re.compile(
    r"\b(?:session[_-]?id|sid|sess|phpsessid|jsessionid|asp\.net_sessionid|cfid|cftoken)="
    r"([A-Za-z0-9_\-]{16,})\b",
    re.IGNORECASE,
)

API_KEY_RE = re.compile(
    r"\b(?:api[_-]?key|api[_-]?token|api[_-]?secret|access[_-]?key|secret[_-]?key)="
    r"([A-Za-z0-9_\-]{16,})\b",
    re.IGNORECASE,
)

OAUTH_TOKEN_RE = re.compile(
    r"\b(?:access[_-]?token|refresh[_-]?token|oauth[_-]?token|bearer[_-]?token)="
    r"([A-Za-z0-9_\-\.]{16,})\b",
    re.IGNORECASE,
)

TOKEN_IN_URL_RE = re.compile(
    r"(?i)(?:token|session|jwt|auth|api_key|access_token|refresh_token|sid|bearer|cookie)"
    r"=([A-Za-z0-9_\-\.]{16,})",
)

ALGORITHM_SECURITY = {
    "none": ("critical", "No signature verification required"),
    "None": ("critical", "No signature verification required"),
    "nOnE": ("critical", "No signature verification required"),
    "HS256": ("medium", "Symmetric signing - vulnerable to brute force if weak secret"),
    "HS384": ("medium", "Symmetric signing - vulnerable to brute force if weak secret"),
    "HS512": ("medium", "Symmetric signing - vulnerable to brute force if weak secret"),
    "RS256": ("low", "Asymmetric signing - secure if private key is protected"),
    "RS384": ("low", "Asymmetric signing - secure if private key is protected"),
    "RS512": ("low", "Asymmetric signing - secure if private key is protected"),
    "ES256": ("low", "Elliptic curve signing - secure"),
    "ES384": ("low", "Elliptic curve signing - secure"),
    "ES512": ("low", "Elliptic curve signing - secure"),
    "PS256": ("low", "RSA-PSS signing - secure"),
    "PS384": ("low", "RSA-PSS signing - secure"),
    "PS512": ("low", "RSA-PSS signing - secure"),
}

THIRTY_DAYS_SECONDS = 30 * 24 * 60 * 60
TWENTY_FOUR_HOURS_SECONDS = 24 * 60 * 60
ONE_HOUR_SECONDS = 60 * 60

SET_COOKIE_RE = re.compile(
    r"(?i)(?P<name>[^=;]+)=(?P<value>[^;]+)"
    r"(?:;\s*(?P<attributes>[^,]+))?",
)
