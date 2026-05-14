"""Constants and configuration for helper utilities."""

import re

# Re-export from core layer for backward compatibility
from src.core.utils.param_types import (
    IDOR_PARAM_NAMES,
    REDIRECT_PARAM_NAMES,
    SSRF_PARAM_NAMES,
    TOKEN_PARAM_NAMES,
)

__all__ = [
    "SCHEMA_VERSION",
    "AUTH_PATH_HINTS",
    "STATIC_PATH_HINTS",
    "REDIRECT_PATH_HINTS",
    "API_PATH_HINTS",
    "LOW_VALUE_ENDPOINT_TYPES",
    "TRACKING_PARAM_PREFIXES",
    "TRACKING_PARAM_NAMES",
    "NESTED_REDIRECT_PARAM_NAMES",
    "LOW_VALUE_PATH_HINTS",
    "SELF_ENDPOINT_HINTS",
    "THIRD_PARTY_AUTH_HOSTS",
    "REDIRECT_PARAM_NAMES",
    "IDOR_PARAM_NAMES",
    "SSRF_PARAM_NAMES",
    "TOKEN_PARAM_NAMES",
    "NOISE_FIELD_NAMES",
    "AUTH_SKIP_PARAMS",
    "AUTH_AWARE_PARAMS",
    "JSON_CONTENT_TOKENS",
    "HIGH_RISK_LOCATION_ORDER",
    "LOCATION_SEVERITY",
    "JWT_LIKE_RE",
    "DNS_LIKE_RE",
    "AWS_KEY_RE",
    "API_KEY_RE",
    "GITHUB_TOKEN_RE",
    "SLACK_TOKEN_RE",
    "STRIPE_KEY_RE",
    "LONG_ALNUM_RE",
    "HEX_ONLY_RE",
    "UUID_RE",
    "IP_RE",
    "AUTH_FLOW_PATHS",
]

SCHEMA_VERSION = 2
AUTH_PATH_HINTS = ("/auth", "/login", "/oauth", "/signin", "/signup", "/session")
STATIC_PATH_HINTS = ("/assets", "/favicon", "/images", "/js/", "/robots.txt", "/static", "/styles/")
REDIRECT_PATH_HINTS = ("/bounce", "/continue", "/redirect", "/relay", "/return")
API_PATH_HINTS = ("/api/", "/graphql", "/rest/", "/swagger", "/v1/", "/v2/")
LOW_VALUE_ENDPOINT_TYPES = {"AUTH", "STATIC"}
TRACKING_PARAM_PREFIXES = ("utm_",)
TRACKING_PARAM_NAMES = {"_ga", "_gl", "cxtrends", "fbclid", "gclid", "mc_cid", "mc_eid"}
NESTED_REDIRECT_PARAM_NAMES = {
    "continue",
    "next",
    "redirect",
    "redirect_to",
    "return",
    "return_to",
    "state",
    "url",
}
LOW_VALUE_PATH_HINTS = ("/access/unauthenticated", "/help", "/hc/")
SELF_ENDPOINT_HINTS = ("/me", "/users/me", "/users/me.json")
THIRD_PARTY_AUTH_HOSTS = (
    "facebook.com",
    "google.com",
    "accounts.google.com",
    "apple.com",
    "login.microsoftonline.com",
)

NOISE_FIELD_NAMES = {
    "id",
    "uuid",
    "created_at",
    "updated_at",
    "timestamp",
    "ts",
    "request_id",
    "trace_id",
}

AUTH_SKIP_PARAMS = {
    "token",
    "session",
    "jwt",
    "auth",
    "api_key",
    "access_token",
    "refresh_token",
    "client_id",
    "client_secret",
    "authorization",
    "bearer",
    "cookie",
    "sid",
    "phpsessid",
}

AUTH_AWARE_PARAMS = {
    "user_id",
    "user",
    "account",
    "account_id",
    "org",
    "org_id",
    "tenant",
    "tenant_id",
    "team",
    "team_id",
    "project",
    "project_id",
    "workspace",
    "workspace_id",
}

JSON_CONTENT_TOKENS = (
    "application/json",
    "application/ld+json",
    "application/problem+json",
    "text/json",
    "+json",
)

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

# Pre-compiled regex patterns
JWT_LIKE_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
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

AUTH_FLOW_PATHS = frozenset(
    {
        "login",
        "signin",
        "sign-in",
        "log-in",
        "authenticate",
        "auth",
        "logout",
        "signout",
        "sign-out",
        "log-out",
        "register",
        "signup",
        "sign-up",
        "signon",
        "sign-on",
        "oauth",
        "openid",
        "sso",
        "saml",
        "callback",
        "authorize",
        "token",
        "refresh",
        "reset-password",
        "forgot-password",
        "verify",
        "confirm",
        "activate",
        "deactivate",
        "session",
        "sessions",
        "login-check",
        "auth-check",
    }
)
