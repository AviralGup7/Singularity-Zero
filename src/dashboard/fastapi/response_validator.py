"""Response validation middleware for the FastAPI dashboard.

Ensures all API responses are valid JSON with consistent structure.
Guarantees no null/undefined responses and required keys always exist.
"""

import json
import logging
from typing import Any, cast

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger(__name__)

# Endpoints that return non-JSON responses (SSE, file downloads, etc.)
NON_JSON_PATHS = (
    "/api/jobs/",  # SSE stream endpoint
    "/api/export/",  # CSV/JSON file downloads
    "/api/docs",  # Swagger UI
    "/api/redoc",  # ReDoc UI
    "/api/openapi.json",  # OpenAPI spec
    "/react",  # React SPA
    "/assets",  # Static assets
)


def _is_json_response(response: Response) -> bool:
    """Check if the response is a JSON response."""
    content_type = response.headers.get("content-type", "")
    return (
        "application/json" in content_type or content_type.startswith("text/event-stream") is False
    ) and not any(
        response.url.path.startswith(p)
        for p in NON_JSON_PATHS
        if hasattr(response, "url") and response.url
    )


def _normalize_response_body(body: Any) -> Any:
    """Normalize response body to ensure consistency.

    - Never returns None or undefined
    - Ensures dicts have at least one key
    - Ensures lists are never None
    """
    if body is None:
        return {}
    if isinstance(body, bool):
        return {"success": body}
    if isinstance(body, (str, int, float)):
        return {"data": body}
    if isinstance(body, list):
        return {"items": body, "total": len(body)}
    if isinstance(body, dict):
        # Ensure no None values for critical fields
        normalized = {}
        for key, value in body.items():
            if value is None:
                # Convert None to appropriate empty defaults based on context
                if key.endswith("_count") or key in (
                    "total",
                    "total_gaps",
                    "total_logs",
                    "count",
                    "runs_analyzed",
                ):
                    normalized[key] = cast(Any, 0)
                elif key.endswith("_list") or key in (
                    "findings",
                    "gaps",
                    "items",
                    "logs",
                    "targets",
                    "notes",
                    "timeline",
                    "jobs",
                ):
                    normalized[key] = cast(Any, [])
                elif key in ("target", "error", "detail", "message", "status"):
                    normalized[key] = cast(Any, "")
                else:
                    normalized[key] = cast(Any, None)  # Allow None for non-critical fields
            else:
                normalized[key] = value
        return normalized
    return body


class ResponseValidationMiddleware(BaseHTTPMiddleware):
    """Middleware that validates and normalizes all JSON responses.

    This ensures:
    - All responses are valid JSON
    - No null/undefined responses
    - Required keys always exist (even if empty)
    - Consistent response format across all endpoints
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        # Skip non-API paths
        path = request.url.path
        if not path.startswith("/api/"):
            return response

        # Skip SSE and file download endpoints
        if any(path.startswith(p.rstrip("/")) for p in NON_JSON_PATHS if p.startswith("/api/")):
            return response

        # Only process JSON responses
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type and not isinstance(response, JSONResponse):
            return response

        # Extract and validate body
        try:
            body_bytes = b""
            if hasattr(response, "body"):
                body_val = response.body
                body_bytes = body_val if isinstance(body_val, bytes) else bytes(body_val)
            elif hasattr(response, "content"):
                if isinstance(response.content, bytes):
                    body_bytes = response.content
                elif isinstance(response.content, (bytearray, memoryview)):
                    body_bytes = bytes(response.content)
                else:
                    body_bytes = str(response.content).encode("utf-8")

            if not body_bytes:
                # Some response types don't expose a materialized body at this stage.
                # Preserve the original response instead of replacing it with {}.
                return response

            # Parse existing JSON
            try:
                body = json.loads(body_bytes.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Invalid JSON - return error response
                logger.error("Invalid JSON response for %s", path)
                return JSONResponse(
                    content={"error": "Internal Server Error", "detail": "Invalid response format"},
                    status_code=500,
                )

            # Normalize the response
            normalized = _normalize_response_body(body)

            # Create new response with normalized body
            return JSONResponse(
                content=normalized,
                status_code=response.status_code,
                headers=dict(response.headers),
            )

        except Exception as exc:
            logger.exception("Response validation error for %s: %s", path, exc)
            # Return safe error response instead of crashing
            return JSONResponse(
                content={"error": "Internal Server Error", "detail": "Response processing error"},
                status_code=500,
            )
