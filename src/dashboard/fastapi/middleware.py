"""Custom middleware for the FastAPI dashboard."""

import logging
import secrets
import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_CSRF_HEADER_NAME = "X-CSRF-Token"
_CSRF_COOKIE_NAME = "csrf_token"
_CSRF_EXEMPT_PATHS = (
    "/api/auth/token",
    "/api/auth/login",
    "/api/csrf-token",
)


def issue_csrf_token() -> str:
    """Generate a fresh CSRF token. Exposed so routers can mint a token for SPAs."""
    return secrets.token_urlsafe(32)


class RequestTimingMiddleware(BaseHTTPMiddleware):
    """Middleware for measuring and logging request processing time and request ID tracing."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        import uuid

        # TODO: Propagate this request_id to downstream pipeline stages via contextvars
        # so that every log line in a request's lifecycle can carry the same correlation ID.
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = request_id

        # Use monotonic time so that clock adjustments can't make the
        # reported latency go negative or roll backwards.
        start_time = time.monotonic()
        response = await call_next(request)
        process_time = time.monotonic() - start_time

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{process_time:.6f}"
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware for adding security headers to HTTP responses.

    The middleware now applies the full set of headers from
    ``src.dashboard.fastapi.validation.security_headers`` (CSP, HSTS,
    Permissions-Policy, etc.) in addition to the legacy ``X-XSS-Protection``
    header. Centralising the policy in ``validation.py`` means the CSP
    and HSTS are no longer silently dropped from the response.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Import lazily to avoid a circular import at module load time.
        from src.dashboard.fastapi.validation import security_headers

        response = await call_next(request)
        for name, value in security_headers().items():
            response.headers[name] = value
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """Double-submit cookie CSRF protection for state-changing requests.

    The middleware now actually validates requests instead of being a no-op:
    * Safe methods (``GET``/``HEAD``/``OPTIONS``) are passed through.
    * Authenticated calls that carry a Bearer token or ``X-API-Key`` are
      exempt because they are not vulnerable to CSRF.
    * For cookie-authenticated state-changing calls, the request must
      include a CSRF token (in the ``X-CSRF-Token`` header) that matches
      the value of the ``csrf_token`` cookie. Mismatched / missing tokens
      result in ``403 Forbidden``.

    Set the ``csrf_token`` cookie via the ``/api/csrf-token`` endpoint and
    have the SPA include the token in the ``X-CSRF-Token`` header on every
    non-safe request.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        method = request.method.upper()
        if method in _SAFE_METHODS:
            return await call_next(request)
        # WebSocket upgrades and the public auth/handshake endpoints are exempt.
        path = request.url.path
        if path in _CSRF_EXEMPT_PATHS or path.startswith("/ws/") or path.startswith("/api/ws/"):
            return await call_next(request)
        # Bearer / API-key auth isn't a CSRF vector.
        if (
            request.headers.get("Authorization", "").lower().startswith("bearer ")
            or request.headers.get("X-API-Key")
        ):
            return await call_next(request)

        cookie_token = request.cookies.get(_CSRF_COOKIE_NAME)
        header_token = request.headers.get(_CSRF_HEADER_NAME)
        if not cookie_token or not header_token:
            logger.warning(
                "CSRF rejection: missing token (path=%s method=%s cookie=%s header=%s)",
                path,
                method,
                bool(cookie_token),
                bool(header_token),
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token missing. Reload the page or re-authenticate."},
            )
        if not secrets.compare_digest(cookie_token, header_token):
            logger.warning(
                "CSRF rejection: token mismatch (path=%s method=%s)", path, method
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token mismatch."},
            )
        return await call_next(request)


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for audit logging dashboard API requests."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        audit_logger = getattr(request.app.state, "audit_logger", None)
        if audit_logger and request.url.path.startswith("/api"):
            try:
                client_ip = request.client.host if request.client else "unknown"
                user_id = getattr(request.state, "user_id", None) or "anonymous"
                correlation_id = getattr(request.state, "request_id", None)
                audit_logger.log(
                    event=f"api.access.{request.method.lower()}",
                    user_id=user_id,
                    source_ip=client_ip,
                    resource_id=request.url.path,
                    correlation_id=correlation_id,
                    details={
                        "method": request.method,
                        "path": request.url.path,
                        "status_code": response.status_code,
                    },
                )
            except Exception:
                pass
        return response
