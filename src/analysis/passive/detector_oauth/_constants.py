"""Constants and configuration for OAuth misconfiguration detection."""

__all__ = [
    "OAUTH_AUTHZ_PATHS",
    "OAUTH_TOKEN_PATHS",
    "OAUTH_WELL_KNOWN_PATHS",
    "DANGEROUS_SCOPES",
    "OVERLY_PERMISSIVE_SCOPE_COMBOS",
    "OAUTH_MISCONFIGURATION_PROBE_SPEC",
]

OAUTH_AUTHZ_PATHS = {
    "/authorize",
    "/oauth/authorize",
    "/oauth2/authorize",
    "/oauth2/auth",
    "/oauth/auth",
    "/connect/authorize",
    "/openid/authorize",
    "/oidc/authorize",
}

OAUTH_TOKEN_PATHS = {
    "/token",
    "/oauth/token",
    "/oauth2/token",
    "/connect/token",
    "/openid/token",
    "/oidc/token",
}

OAUTH_WELL_KNOWN_PATHS = {
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
}

DANGEROUS_SCOPES = {
    "openid",
    "profile",
    "email",
    "phone",
    "address",
    "offline_access",
    "admin",
    "admin.read",
    "admin.write",
    "full_access",
    "read",
    "write",
    "delete",
    "manage",
    "superuser",
    "root",
}

OVERLY_PERMISSIVE_SCOPE_COMBOS = [
    {"openid", "profile", "email", "phone", "address"},
    {"admin", "write", "delete"},
    {"offline_access", "admin"},
    {"full_access"},
    {"superuser"},
]

OAUTH_MISCONFIGURATION_PROBE_SPEC = {
    "key": "oauth_misconfiguration_detector",
    "label": "OAuth Misconfiguration Detector",
    "description": "Passive analyzer for OAuth 2.0 / OIDC misconfigurations including missing state parameter, insecure redirect URIs, implicit grant flow usage, missing PKCE, exposed tokens, and open redirects.",
    "group": "passive",
}
