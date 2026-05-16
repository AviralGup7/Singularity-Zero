"""CORS configuration for the Cyber Security Test Pipeline.

DEPRECATED: This module is no longer used.
The dashboard now uses FastAPI's built-in CORSMiddleware directly (app.py).
This file is kept for reference only. Remove it once fully deprecated.

Provides configurable Cross-Origin Resource Sharing middleware with
preflight request handling, credential support, and method/header
restrictions.

Classes:
    CORSMiddleware: Starlette-compatible CORS middleware

Usage:
    from src.infrastructure.security.cors import CORSMiddleware
    from src.infrastructure.security.config import SecurityConfig

    config = SecurityConfig()
    app.add_middleware(CORSMiddleware, config=config)
"""

import re
from typing import Any, cast

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.security.config import SecurityConfig

logger = get_pipeline_logger(__name__)


class CORSMiddleware(BaseHTTPMiddleware):
    """Configurable CORS middleware for the FastAPI dashboard.

    Provides secure CORS configuration with:
    - Configurable allowed origins with pattern matching
    - Preflight (OPTIONS) request handling
    - Credential handling (cookies, authorization headers)
    - Method and header restrictions
    - Exposed header configuration

    Attributes:
        config: Security configuration.
        _allowed_origins: Compiled origin patterns.
        _allowed_methods: Set of allowed HTTP methods.
        _allowed_headers: Set of allowed request headers.
        _expose_headers: Headers to expose to the browser.
        _max_age: Preflight cache duration in seconds.
        _allow_credentials: Whether to allow credentials.
    """

    SIMPLE_METHODS = {"GET", "HEAD", "POST"}
    SIMPLE_HEADERS = {"accept", "accept-language", "content-language", "content-type"}
    SAFE_CONTENT_TYPES = {
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
    }

    def __init__(
        self,
        config: SecurityConfig,
        allowed_origins: list[str] | None = None,
        allow_credentials: bool | None = None,
        allowed_methods: list[str] | None = None,
        allowed_headers: list[str] | None = None,
        expose_headers: list[str] | None = None,
        max_age: int | None = None,
    ) -> None:
        """Initialize the CORS middleware.

        Args:
            config: Security configuration.
            allowed_origins: Override for allowed origins.
            allow_credentials: Override for credential support.
            allowed_methods: Override for allowed methods.
            allowed_headers: Override for allowed headers.
            expose_headers: Override for exposed headers.
            max_age: Override for preflight cache duration.
        """
        super().__init__(cast(Any, None))
        self.config = config
        cors_config = config.cors

        self._allowed_origins = allowed_origins or cors_config.allowed_origins
        self._allow_credentials = (
            allow_credentials if allow_credentials is not None else cors_config.allow_credentials
        )
        self._allowed_methods = allowed_methods or cors_config.allowed_methods
        self._allowed_headers = allowed_headers or cors_config.allowed_headers
        self._expose_headers = expose_headers or cors_config.expose_headers
        self._max_age = max_age or cors_config.max_age

        self._origin_patterns = self._compile_origin_patterns(self._allowed_origins)
        self._methods_upper = {m.upper() for m in self._allowed_methods}
        self._headers_lower = (
            None if "*" in self._allowed_headers else {h.lower() for h in self._allowed_headers}
        )

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process the request with CORS handling.

        Args:
            request: Incoming HTTP request.
            call_next: Next middleware/handler in the chain.

        Returns:
            Response with CORS headers.
        """
        origin = request.headers.get("origin")

        if not origin:
            return await call_next(request)

        origin_allowed = self._is_origin_allowed(origin)

        if request.method == "OPTIONS":
            return self._handle_preflight(request, origin, origin_allowed)

        response = await call_next(request)

        if origin_allowed:
            self._add_cors_headers(response, origin)

        return response

    def _handle_preflight(
        self,
        request: Request,
        origin: str,
        origin_allowed: bool,
    ) -> Response:
        """Handle CORS preflight (OPTIONS) request.

        Args:
            request: Incoming OPTIONS request.
            origin: Request origin header.
            origin_allowed: Whether the origin is in the allowlist.

        Returns:
            204 response with CORS headers or 403 if denied.
        """
        headers: dict[str, str] = {}

        if origin_allowed:
            headers["Access-Control-Allow-Origin"] = origin

            if self._allow_credentials:
                headers["Access-Control-Allow-Credentials"] = "true"

            requested_method = request.headers.get("access-control-request-method", "")
            if requested_method and requested_method.upper() in self._methods_upper:
                headers["Access-Control-Allow-Methods"] = ", ".join(sorted(self._methods_upper))

            requested_headers = request.headers.get("access-control-request-headers", "")
            if requested_headers:
                if self._headers_lower is None:
                    headers["Access-Control-Allow-Headers"] = "*"
                else:
                    req_headers = {h.strip().lower() for h in requested_headers.split(",")}
                    disallowed = req_headers - self._headers_lower - self.SIMPLE_HEADERS
                    if disallowed:
                        logger.warning(
                            "CORS preflight denied: disallowed headers %s from %s",
                            disallowed,
                            origin,
                        )
                        return PlainTextResponse(
                            status_code=403,
                            content="CORS: Disallowed request headers",
                        )
                    headers["Access-Control-Allow-Headers"] = requested_headers

            headers["Access-Control-Max-Age"] = str(self._max_age)
        else:
            logger.warning("CORS preflight denied: origin %s not allowed", origin)
            return PlainTextResponse(
                status_code=403,
                content="CORS: Origin not allowed",
            )

        return PlainTextResponse(status_code=204, headers=headers)

    def _add_cors_headers(self, response: Response, origin: str) -> None:
        """Add CORS headers to a response.

        Args:
            response: Response to modify.
            origin: Request origin.
        """
        response.headers["Access-Control-Allow-Origin"] = origin

        if self._allow_credentials:
            response.headers["Access-Control-Allow-Credentials"] = "true"

        if self._expose_headers:
            response.headers["Access-Control-Expose-Headers"] = ", ".join(self._expose_headers)

        response.headers["Vary"] = "Origin"

    def _is_origin_allowed(self, origin: str) -> bool:
        """Check if an origin is allowed.

        Args:
            origin: Origin header value.

        Returns:
            True if the origin is allowed.
        """
        if "*" in self._allowed_origins:
            if self._allow_credentials:
                logger.warning(
                    "CORS: Wildcard origin with credentials is insecure. "
                    "Specify explicit origins instead."
                )
            return True

        for pattern in self._origin_patterns:
            if pattern.fullmatch(origin):
                return True

        return False

    def _compile_origin_patterns(self, origins: list[str]) -> list[re.Pattern[str]]:
        """Compile origin strings into regex patterns.

        Args:
            origins: List of origin strings or regex patterns.

        Returns:
            List of compiled regex patterns.
        """
        patterns: list[re.Pattern[str]] = []
        for origin in origins:
            if origin == "*":
                patterns.append(re.compile(r".*"))
            else:
                escaped = re.escape(origin)
                patterns.append(re.compile(escaped))
        return patterns
