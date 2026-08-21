"""Extra keyword rules feeding taxonomy.classify_key."""

from __future__ import annotations

# (needle, family) — longest needles should be checked first by callers if needed.
FAMILY_RULES: tuple[tuple[str, str], ...] = (
    ("graphql", "api"),
    ("grpc", "api"),
    ("websocket", "api"),
    ("openapi", "api"),
    ("swagger", "api"),
    ("sqli", "injection"),
    ("xss", "injection"),
    ("ssti", "injection"),
    ("xpath", "injection"),
    ("nosql", "injection"),
    ("ldap", "injection"),
    ("command_injection", "injection"),
    ("ssrf", "ssrf"),
    ("idor", "access"),
    ("bola", "access"),
    ("auth_bypass", "access"),
    ("access_control", "access"),
    ("privilege", "access"),
    ("jwt", "access"),
    ("session", "access"),
    ("cors", "misconfig"),
    ("csp", "misconfig"),
    ("hsts", "misconfig"),
    ("header", "misconfig"),
    ("cookie_security", "misconfig"),
    ("tls", "crypto"),
    ("ssl", "crypto"),
    ("upload", "upload"),
    ("path_traversal", "lfi"),
    ("lfi", "lfi"),
    ("rfi", "lfi"),
    ("race", "runtime"),
    ("cache", "cache"),
    ("takeover", "dns"),
    ("dns", "dns"),
    ("waf", "defense"),
    ("rate_limit", "defense"),
    ("smuggl", "protocol"),
    ("h2", "protocol"),
    ("http2", "protocol"),
    ("deserial", "rce"),
    ("rce", "rce"),
    ("xxe", "injection"),
    ("crlf", "injection"),
    ("redirect", "access"),
    ("csrf", "access"),
)


def family_for(key: str) -> str:
    lowered = key.lower()
    for needle, family in FAMILY_RULES:
        if needle in lowered:
            return family
    return "other"
