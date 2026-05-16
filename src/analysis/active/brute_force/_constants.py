"""Constants and configuration for brute force resistance probing."""

__all__ = [
    "AUTH_ENDPOINT_PATTERNS",
    "INVALID_USERNAME",
    "INVALID_PASSWORD",
    "COMMON_USERNAMES",
    "COMMON_PASSWORDS",
    "PROBE_CONFIDENCE",
    "PROBE_SEVERITY",
    "BRUTE_FORCE_PROBE_SPEC",
]

AUTH_ENDPOINT_PATTERNS = [
    "login",
    "signin",
    "sign-in",
    "sign_in",
    "auth",
    "authenticate",
    "authentication",
    "token",
    "oauth/token",
    "oauth2/token",
    "access_token",
    "refresh_token",
    "session",
    "sessions",
    "signin-oidc",
    "signin-google",
    "signin-facebook",
    "signin-github",
    "signin-twitter",
    "signin-microsoft",
    "signin-apple",
    "signin-amazon",
    "signin-paypal",
    "signin-linkedin",
    "signin-discord",
    "signin-slack",
    "signin-twitch",
    "signin-spotify",
    "signin-steam",
    "signin-epic",
    "signin-ubisoft",
    "signin-battlenet",
    "signin-origin",
    "signin-rockstar",
    "signin-ea",
    "signin-valve",
    "signin-gog",
    "signin-humble",
    "signin-itch",
    "signin-itch-io",
    "signin-itchio",
]

INVALID_USERNAME = "this_user_does_not_exist_xyz123"
INVALID_PASSWORD = "wrong_password_attempt_123"  # noqa: S105
COMMON_USERNAMES = ["admin", "user", "test", "administrator", "root"]
COMMON_PASSWORDS = ["password", "123456", "password123", "admin123", "letmein"]

PROBE_CONFIDENCE = {
    "no_rate_limiting": 0.85,
    "no_account_lockout": 0.80,
    "no_captcha": 0.70,
    "no_progressive_delay": 0.75,
    "no_ip_blocking": 0.82,
    "username_enumeration": 0.88,
    "timing_attack_vulnerable": 0.72,
    "credential_stuffing_vulnerable": 0.85,
    "weak_rate_limiting": 0.78,
    "inconsistent_error_messages": 0.82,
    "missing_auth_headers": 0.65,
}

PROBE_SEVERITY = {
    "no_rate_limiting": "high",
    "no_account_lockout": "high",
    "no_captcha": "medium",
    "no_progressive_delay": "medium",
    "no_ip_blocking": "high",
    "username_enumeration": "high",
    "timing_attack_vulnerable": "medium",
    "credential_stuffing_vulnerable": "high",
    "weak_rate_limiting": "medium",
    "inconsistent_error_messages": "high",
    "missing_auth_headers": "low",
}

BRUTE_FORCE_PROBE_SPEC = {
    "key": "brute_force_resistance_probe",
    "label": "Brute Force Resistance Probe",
    "description": "Actively test authentication endpoints for brute force resistance weaknesses.",
    "group": "active",
    "input_kind": "priority_urls_and_cache",
}
