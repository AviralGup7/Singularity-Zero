"""Security HTTP headers for the Cyber Security Test Pipeline.

Provides middleware for adding security headers to all responses
including Content-Security-Policy, HSTS, X-Frame-Options, etc.

Classes:
    SecurityHeadersMiddleware: Starlette middleware for security headers

Usage:
    from src.infrastructure.security.headers import SecurityHeadersMiddleware
    from src.infrastructure.security.config import SecurityConfig

    config = SecurityConfig()
    app.add_middleware(SecurityHeadersMiddleware, config=config)
"""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from src.infrastructure.security.config import SecurityConfig
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware that adds security headers to all responses.

    Adds the following headers:
    - Strict-Transport-Security: Enforces HTTPS
    - X-Content-Type-Options: Prevents MIME-type sniffing
    - X-Frame-Options: Prevents clickjacking
    - Content-Security-Policy: Restricts resource loading
    - X-XSS-Protection: Legacy XSS filter
    - Referrer-Policy: Controls referrer information
    - Permissions-Policy: Restricts browser features
    - Cache-Control: For sensitive endpoints

    Attributes:
        config: Security configuration.
        _headers: Dict of header name to value.
        _sensitive_paths: Paths that get no-cache headers.
    """

    SENSITIVE_PATH_PREFIXES = (
        "/api/auth",
        "/api/admin",
        "/api/keys",
        "/api/users",
    )

    def __init__(
        self,
        config: SecurityConfig,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Initialize the security headers middleware.

        Args:
            config: Security configuration.
            headers: Override for security headers.
        """
        super().__init__(None)
        self.config = config
        hc = config.headers

        self._headers = headers or {
            "Strict-Transport-Security": hc.strict_transport_security,
            "X-Content-Type-Options": hc.x_content_type_options,
            "X-Frame-Options": hc.x_frame_options,
            "Content-Security-Policy": hc.content_security_policy,
            "X-XSS-Protection": hc.x_xss_protection,
            "Referrer-Policy": hc.referrer_policy,
            "Permissions-Policy": hc.permissions_policy,
        }
        self._cache_control_sensitive = hc.cache_control_sensitive

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Add security headers to the response.

        Args:
            request: Incoming HTTP request.
            call_next: Next middleware/handler.

        Returns:
            Response with security headers.
        """
        response = await call_next(request)

        for header, value in self._headers.items():
            if header not in response.headers:
                response.headers[header] = value

        if self._is_sensitive_path(request.url.path):
            response.headers["Cache-Control"] = self._cache_control_sensitive
            response.headers["Pragma"] = "no-cache"

        response.headers["X-Content-Type-Options"] = "nosniff"
        if "X-Frame-Options" not in response.headers:
            response.headers["X-Frame-Options"] = "DENY"

        if "X-Permitted-Cross-Domain-Policies" not in response.headers:
            response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        if "Cross-Origin-Opener-Policy" not in response.headers:
            response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        if "Cross-Origin-Resource-Policy" not in response.headers:
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        response.headers["X-DNS-Prefetch-Control"] = "off"
        response.headers["X-Download-Options"] = "noopen"

        if "Server" in response.headers:
            del response.headers["Server"]

        return response

    def _is_sensitive_path(self, path: str | None) -> bool:
        """Check if a path should get no-cache headers.

        Args:
            path: Request URL path.

        Returns:
            True if the path is sensitive.
        """
        if not path:
            return False
        return any(path.startswith(p) for p in self.SENSITIVE_PATH_PREFIXES)

    def update_header(self, name: str, value: str) -> None:
        """Update a security header value.

        Args:
            name: Header name.
            value: New header value.
        """
        self._headers[name] = value

    def remove_header(self, name: str) -> bool:
        """Remove a security header.

        Args:
            name: Header name to remove.

        Returns:
            True if the header was found and removed.
        """
        if name in self._headers:
            del self._headers[name]
            return True
        return False

    def get_headers(self) -> dict[str, str]:
        """Get all configured security headers.

        Returns:
            Dict of header name to value.
        """
        return dict(self._headers)
