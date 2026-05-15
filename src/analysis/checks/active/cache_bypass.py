"""Automated 304/204 prevention for security scans.

304 Not Modified responses can mask authorization bypasses because
they return no body content, making comparison impossible.
"""


class CacheBypassMiddleware:
    """Automatically strips cache-related headers to prevent 304 responses.

    304 Not Modified responses can mask authorization bypasses because
    they return no body content, making comparison impossible.
    """

    CACHE_HEADERS: list[str] = [
        "if-none-match",
        "if-modified-since",
        "if-match",
        "if-unmodified-since",
        "if-range",
    ]

    def process_request(self, headers: dict[str, str]) -> dict[str, str]:
        """Strip cache headers from request."""
        return {k: v for k, v in headers.items() if k.lower() not in self.CACHE_HEADERS}

    def add_cache_busting(self, headers: dict[str, str]) -> dict[str, str]:
        """Add cache-busting headers to request."""
        headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        headers["Pragma"] = "no-cache"
        headers["Expires"] = "0"
        return headers

    def process_request_with_cache_bypass(self, headers: dict[str, str]) -> dict[str, str]:
        """Full cache bypass: strip cache headers + add cache-busting."""
        headers = self.process_request(headers)
        headers = self.add_cache_busting(headers)
        return headers
