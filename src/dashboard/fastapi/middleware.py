"""Custom middleware for the FastAPI dashboard."""

import hmac
import json
import logging
import secrets
import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)


class RequestTimingMiddleware(BaseHTTPMiddleware):
    """Middleware for measuring and logging request processing time and request ID tracing."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        import uuid

        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = request_id

        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = str(process_time)
        return response


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """CSRF protection middleware for state-changing requests."""

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
    EXEMPT_PATHS = {
        "/api/health",
        "/api/health/live",
        "/api/health/ready",
        "/api/openapi.json",
        "/api/docs",
        "/api/redoc",
        "/api/auth/token",
        "/api/csp-report",
        "/api/csrf-token",
    }

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        from src.dashboard.fastapi.security import api_security_enabled

        if not api_security_enabled():
            return await call_next(request)

        if request.method in self.SAFE_METHODS:
            response = await call_next(request)
            # Bootstrapping: Set a CSRF cookie on safe requests if not already set
            if not request.cookies.get("csrf_token"):
                token = secrets.token_urlsafe(32)
                response.set_cookie(
                    "csrf_token",
                    token,
                    httponly=True,  # Protected against XSS token theft (Double-Submit cookie with HttpOnly=True)
                    samesite="lax",
                    secure=False,  # Allow secure=False for local development/testing flexibility
                )
            return response

        path = request.url.path
        if path in self.EXEMPT_PATHS or path.startswith("/reports/"):
            return await call_next(request)

        # Defense-in-depth: Verify origin for state-changing requests
        origin = request.headers.get("origin")
        referer = request.headers.get("referer")
        auth = request.headers.get("authorization", "")
        api_key_header = request.headers.get("x-api-key", "")

        # Non-browser clients using Bearer tokens or API keys are exempt from CSRF checks
        if auth.startswith("Bearer ") or api_key_header:
            return await call_next(request)

        if origin:
            expected_host = request.headers.get("host", "")
            if referer and expected_host not in referer:
                logger.warning("CSRF: Origin mismatch: origin=%s, referer=%s", origin, referer)
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "CSRF: Origin verification failed",
                        "detail": "Origin verification failed",
                        "code": "csrf_origin_failed",
                    },
                )

        # Enforce Double-Submit Cookie CSRF protection
        csrf_cookie = request.cookies.get("csrf_token") or request.cookies.get("csrf-token")
        csrf_header = request.headers.get("x-csrf-token") or request.headers.get("X-CSRF-Token")

        if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
            logger.warning(
                "CSRF: Double-submit token mismatch: cookie=%s, header=%s", csrf_cookie, csrf_header
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "CSRF: Token verification failed",
                    "detail": "CSRF token verification failed",
                    "code": "csrf_token_failed",
                },
            )

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware for injecting standard security headers into all responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Security Fix: Remove Server header to avoid technology fingerprinting.
        if "server" in response.headers:
            del response.headers["server"]
        if "Server" in response.headers:
            del response.headers["Server"]
        # Security Fix: Add Permissions-Policy to restrict powerful browser features.
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
        )
        return response


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for audit logging of all sensitive API requests."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # We only audit state-changing operations
        is_sensitive = request.method in {"POST", "PUT", "DELETE", "PATCH"}

        if not is_sensitive:
            return await call_next(request)

        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time

        # Extract user ID and role from auth (if available)
        user_id = "anonymous"
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            user_id = "bearer_token"

        # Try to get user from request state if authentication already happened
        # However, middleware runs before or during routing, so state might not be set yet.
        # But we can try to access it if the route has finished.
        if hasattr(request.state, "user"):
            user_id = request.state.user

        log_data = {
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": round(duration * 1000, 2),
            "ip": request.client.host if request.client else "unknown",
        }

        # Log to the backend AuditLogger if available
        audit_logger = getattr(request.app.state, "audit_logger", None)
        if audit_logger:
            try:
                audit_logger.log(
                    event=f"api.{request.method.lower()}",
                    user_id=user_id,
                    source_ip=log_data["ip"],
                    resource_id=request.url.path,
                    details=log_data,
                    severity="info" if response.status_code < 400 else "warning",
                )
            except Exception as exc:
                logger.debug("Failed to record backend audit log: %s", exc)

        if response.status_code >= 400:
            logger.warning("Audit: Request failed: %s", json.dumps(log_data))
        else:
            logger.info("Audit: Request success: %s", json.dumps(log_data))

        return response
