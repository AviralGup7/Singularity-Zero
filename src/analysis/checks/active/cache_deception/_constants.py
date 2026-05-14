"""Constants and configuration for cache deception probing."""

__all__ = [
    "CHECK_SPEC",
    "STATIC_EXTENSIONS",
    "PATH_TRAVERSAL_VARIANTS",
    "CACHE_FRIENDLY_HEADERS",
    "PUBLIC_CACHE_INDICATORS",
    "NO_CACHE_INDICATORS",
    "SENSITIVE_PATH_HINTS",
]

CHECK_SPEC = {
    "key": "cache_deception_probe",
    "label": "Cache Deception Probe",
    "description": "Actively test for web cache deception by requesting sensitive endpoints with static file extensions and path normalization tricks, checking for cacheable responses containing user-specific data.",
    "group": "active",
    "input_kind": "priority_urls_and_cache",
}

STATIC_EXTENSIONS = [
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".json",
    ".xml",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".txt",
]

PATH_TRAVERSAL_VARIANTS = [
    "/..;/",
    "/%2e%2e/",
    "/..%252f",
    "/%2e%2e%2f",
    "/..%2f",
    "/.;/",
    "/%3b/",
    "/%252e%252e/",
    "/%252e%252e%252f",
]

CACHE_FRIENDLY_HEADERS = frozenset(
    {
        "cache-control",
        "etag",
        "last-modified",
        "expires",
        "age",
        "x-cache",
        "x-cache-hits",
        "x-varnish",
        "via",
        "cf-cache-status",
        "x-served-by",
        "x-timer",
    }
)

PUBLIC_CACHE_INDICATORS = frozenset(
    {
        "public",
        "max-age",
        "s-maxage",
        "stale-while-revalidate",
        "stale-if-error",
    }
)

NO_CACHE_INDICATORS = frozenset(
    {
        "no-store",
        "no-cache",
        "private",
        "must-revalidate",
        "proxy-revalidate",
    }
)

SENSITIVE_PATH_HINTS = frozenset(
    {
        "/profile",
        "/account",
        "/settings",
        "/dashboard",
        "/api/user",
        "/api/account",
        "/api/profile",
        "/me",
        "/user",
        "/admin",
        "/api/me",
        "/api/settings",
        "/api/dashboard",
        "/api/admin",
        "/my",
        "/preferences",
        "/billing",
        "/payment",
        "/orders",
        "/subscriptions",
        "/wallet",
        "/security",
        "/privacy",
        "/personal",
        "/info",
        "/details",
        "/data",
        "/export",
        "/download",
    }
)

AUTH_HEADER_KEYS = frozenset(
    {
        "authorization",
        "x-auth-token",
        "x-api-key",
        "cookie",
        "x-csrf-token",
        "x-request-id",
        "x-session-id",
        "bearer",
    }
)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityPipeline/1.0"
