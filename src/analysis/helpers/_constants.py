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
    "EMAIL_VALUE_RE",
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
    "DEBUG_PATH_HINTS",
    "BACKUP_PATH_HINTS",
    "EXPOSED_PATH_HINTS",
    "TLS_VERSION_RE",
    "CERT_VULN_RE",
    "CIPHER_WEAK_RE",
]

SCHEMA_VERSION = 2
AUTH_PATH_HINTS = ("/auth", "/login", "/oauth", "/signin", "/signup", "/session")
STATIC_PATH_HINTS = (
    "/assets",
    "/favicon",
    "/images",
    "/js/",
    "/robots.txt",
    "/static",
    "/styles/",
    "/css/",
    "/img/",
    "/fonts/",
    "/icons/",
    "/logo",
    "/banner",
)
REDIRECT_PATH_HINTS = ("/bounce", "/continue", "/redirect", "/relay", "/return", "/goto", "/go")
API_PATH_HINTS = (
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/api/v3/",
    "/graphql",
    "/graphql/console",
    "/graphql/playground",
    "/graphiql",
    "/gql",
    "/rest/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/swagger",
    "/swagger-ui",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/redoc",
)
LOW_VALUE_ENDPOINT_TYPES = {"AUTH", "STATIC", "BACKUP"}
TRACKING_PARAM_PREFIXES = ("utm_", "_ga", "_gl", "_ms", "_dc", "_g", "gclid", "fbclid")
TRACKING_PARAM_NAMES = {
    "_ga",
    "_gl",
    "cxtrends",
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "_gid",
    "wbraid",
    "_hsci",
    "dclid",
    "trk",
}
NESTED_REDIRECT_PARAM_NAMES = {
    "continue",
    "next",
    "redirect",
    "redirect_to",
    "return",
    "return_to",
    "state",
    "url",
    "goto",
    "go",
    "dest",
    "destination",
}
LOW_VALUE_PATH_HINTS = (
    "/access/unauthenticated",
    "/help",
    "/hc/",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/",
)
SELF_ENDPOINT_HINTS = (
    "/me",
    "/users/me",
    "/users/me.json",
    "/account",
    "/profile",
    "/my",
    "/self",
    "/current",
)
THIRD_PARTY_AUTH_HOSTS = (
    "facebook.com",
    "google.com",
    "accounts.google.com",
    "apple.com",
    "login.microsoftonline.com",
    "auth0.com",
    "okta.com",
    "oktapreview.com",
    "login.microsoft.com",
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
    "correlation_id",
    "span_id",
    "x_request_id",
    "etag",
    "last_modified",
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
    "x-api-key",
    "x-auth-token",
    "id_token",
    "code",
    "state",
    "nonce",
    "code_verifier",
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
    "customer_id",
    "patient_id",
    "order_id",
    "invoice_id",
    "file_id",
    "document_id",
    "resource_id",
}

JSON_CONTENT_TOKENS = (
    "application/json",
    "application/ld+json",
    "application/problem+json",
    "application/hal+json",
    "application/vnd.api+json",
    "text/json",
    "+json",
    "application/vnd.github+json",
    "application/vnd.error+json",
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

# TLS/crypto vulnerability patterns
TLS_VERSION_RE = re.compile(r"\b(SSLv3|TLSv1\.0|TLSv1\.1|TLS 1\.0|TLS 1\.1)\b", re.IGNORECASE)
CERT_VULN_RE = re.compile(
    r"\b(expired|self\.signed|weak\s+signature|SHA1|MD5|1024\.bit|2048\.bit)\b", re.IGNORECASE
)
CIPHER_WEAK_RE = re.compile(r"\b(RC4|DES|3DES|MD5|NULL|EXPORT|aNULL|eNULL|kNULL)\b", re.IGNORECASE)

# Enhanced endpoint classification hints
DEBUG_PATH_HINTS = (
    "/debug",
    "/actuator",
    "/env",
    "/health",
    "/info",
    "/metrics",
    "/prometheus",
    "/api-docs",
    "/swagger",
    "/swagger-ui",
    "/redoc",
    "/graphql",
    "/graphiql",
    "/gql",
    "/console",
    "/admin",
    "/administrator",
    "/manager",
    "/wp-admin",
    "/phpinfo.php",
    "/server-status",
    "/.git",
    "/.env",
    "/config",
    "/backup",
    "/db",
    "/sql",
    "/dump",
)
BACKUP_PATH_HINTS = (
    ".bak",
    ".old",
    ".orig",
    ".swp",
    ".save",
    "~",
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".gz",
    ".sql",
    ".sqlite",
    ".db",
    ".dump",
    "backup",
    "old",
    "bak",
)
EXPOSED_PATH_HINTS = (
    "/api/v1/docs",
    "/api/v2/docs",
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/redoc",
    "/graphql",
    "/graphql/console",
    "/graphql/playground",
)

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
        "mfa",
        "totp",
        "webauthn",
        "passkey",
        "magic-link",
        "invite",
        "accept-invite",
        "forgot",
        "recover",
        "unlock",
        "reset",
        "challenge",
        "consent",
    }
)
