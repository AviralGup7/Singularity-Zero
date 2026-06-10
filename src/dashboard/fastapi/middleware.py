"""Custom middleware for the FastAPI dashboard."""

import contextvars
import logging
import os
import secrets
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

# Context variable for propagating request_id to downstream pipeline stages.
request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_CSRF_HEADER_NAME = "X-CSRF-Token"
_CSRF_COOKIE_NAME = "csrf_token"
_CSRF_EXEMPT_PATHS = (
    "/api/auth/token",
    "/api/auth/login",
    "/api/csrf-token",
    # CSP violation reports are POSTed by the browser from a violating
    # page; the request does not carry cookies, so CSRF does not apply.
    "/api/csp-report",
)

# Bug #29 fix: which forwarded-client-header keys we accept. We use
# ``X-Forwarded-For`` (the de-facto standard) and additionally recognise
# the newer ``Forwarded`` RFC 7239 header. We deliberately do NOT trust
# the right-most value (the one nearest the proxy) because that is the
# address the operator's proxy adds; the left-most is the original
# client. We also cap the number of hops we'll honour to avoid abuse
# via arbitrarily long header chains.
_FORWARDED_HEADER = "X-Forwarded-For"
_FORWARDED_RFC7239 = "Forwarded"
_MAX_FORWARDED_HOPS = 8


def _extract_real_client_ip(request: Request) -> str:
    """Return the original client IP for audit logging.

    Bug #29 fix: ``request.client.host`` is the address of the
    reverse proxy in any production deployment. We honour
    ``X-Forwarded-For`` (left-most hop) when present, fall back to
    the RFC 7239 ``Forwarded`` header, and only use the socket peer
    as a last resort.
    """
    fwd_for = request.headers.get(_FORWARDED_HEADER, "")
    if fwd_for:
        # Take the left-most IP - that's the original client. Limit the
        # split depth so a malicious client cannot OOM the audit log.
        hops = [h.strip() for h in fwd_for.split(",") if h.strip()][:_MAX_FORWARDED_HOPS]
        if hops:
            return hops[0]
    rfc7239 = request.headers.get(_FORWARDED_RFC7239, "")
    if rfc7239:
        # Parsing ``Forwarded: for=ip;by=...;...`` - find the first
        # ``for=`` token. ``ip`` may be quoted or wrapped in ``[]``
        # for IPv6.
        for part in rfc7239.split(";"):
            part = part.strip()
            if part.lower().startswith("for="):
                ip = part[4:].strip().strip('"')
                if ip.startswith("[") and "]" in ip:
                    ip = ip[1 : ip.index("]")]
                if ip:
                    return ip
    if request.client is not None:
        return request.client.host
    return "unknown"


def issue_csrf_token() -> str:
    """Generate a fresh CSRF token. Exposed so routers can mint a token for SPAs."""
    return secrets.token_urlsafe(32)


class RequestTimingMiddleware(BaseHTTPMiddleware):
    """Middleware for measuring and logging request processing time and request ID tracing."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
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
        # When auth is disabled (development mode), CSRF protection is
        # disabled too. Otherwise the SPA / curl-based smoke tests cannot
        # exercise endpoints that would otherwise need a CSRF cookie.
        if os.getenv("DASHBOARD_AUTH_DISABLED", "").lower() in {"1", "true", "yes"}:
            return await call_next(request)
        # Bearer / API-key auth isn't a CSRF vector.
        if request.headers.get("Authorization", "").lower().startswith(
            "bearer "
        ) or request.headers.get("X-API-Key"):
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
            logger.warning("CSRF rejection: token mismatch (path=%s method=%s)", path, method)
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
                # Bug #29 fix: previously the audit log always used
                # ``request.client.host``, which is the address of the
                # reverse proxy / load balancer when the dashboard
                # runs behind one. Forensics and rate-limiting based on
                # the audit log were useless in any non-trivial
                # deployment. We now prefer the left-most IP from
                # ``X-Forwarded-For`` (set by the trusted reverse proxy)
                # and fall back to the connection's peer.
                client_ip = _extract_real_client_ip(request)
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
            except (OSError, ValueError, TypeError, AttributeError) as log_exc:
                logger.debug("Audit log write failed: %s", log_exc)
        return response
