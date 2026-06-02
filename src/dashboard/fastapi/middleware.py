"""Custom middleware for the FastAPI dashboard."""

import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


class RequestTimingMiddleware(BaseHTTPMiddleware):
    """Middleware for measuring and logging request processing time and request ID tracing."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        import uuid

        # TODO: Propagate this request_id to downstream pipeline stages via contextvars
        # so that every log line in a request's lifecycle can carry the same correlation ID.
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = request_id

        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = str(process_time)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware for adding security headers to HTTP responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """Middleware for protecting state-changing requests against CSRF."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
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
