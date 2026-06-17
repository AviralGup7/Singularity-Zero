"""HTTP request metrics middleware for per-endpoint latency tracking.

Provides Prometheus histograms for request latency decomposed by
method, route template, and status code. Includes cardinality controls
to prevent label explosion from high-cardinality path parameters.

Usage:
    from src.dashboard.fastapi.http_metrics import HTTPMetricsMiddleware

    app.add_middleware(HTTPMetricsMiddleware)
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Match, Route

# Path normalization patterns: replace high-cardinality segments with placeholders
_PATH_NORMALIZERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "{uuid}"),
    (re.compile(r"\d+"), "{id}"),
    (re.compile(r"[0-9a-f]{40}", re.I), "{sha}"),
    (re.compile(r"[0-9a-f]{64}", re.I), "{sha256}"),
]

# Maximum unique route templates to prevent unbounded cardinality
_MAX_ROUTE_TEMPLATES = 256

# Bucket boundaries optimized for HTTP latency (seconds)
_HTTP_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)


def _normalize_path(path: str) -> str:
    """Normalize a URL path to a template string.

    Replaces UUIDs, numeric IDs, and hex hashes with placeholders
    to bound label cardinality.

    Args:
        path: Raw URL path.

    Returns:
        Normalized path template.
    """
    normalized = path
    for pattern, replacement in _PATH_NORMALIZERS:
        normalized = pattern.sub(replacement, normalized)
    return normalized


class HTTPMetricsMiddleware(BaseHTTPMiddleware):
    """Middleware that records per-endpoint HTTP latency histograms.

    Tracks:
    - `cyber_pipeline_http_request_duration_seconds` (histogram by method, route, status)
    - `cyber_pipeline_http_requests_total` (counter by method, route, status)
    - `cyber_pipeline_http_request_errors_total` (counter by method, route, status_class)

    Route templates are normalized to prevent cardinality explosion.
    Maximum of 256 unique route templates are tracked; additional routes
    are bucketed under `__other__`.
    """

    def __init__(self, app: Any, **kwargs: Any) -> None:
        super().__init__(app, **kwargs)
        self._seen_routes: set[str] = set()
        self._route_lookup: dict[str, str] = {}
        self._method_labels: defaultdict[str, int] = defaultdict(int)

    def _resolve_route(self, request: Request) -> str:
        """Resolve the request path to a route template.

        Uses Starlette's routing to find the matching route pattern,
        falling back to normalized path if no route matches.
        """
        path = request.url.path

        # Check cache first
        cache_key = f"{request.method}:{path}"
        if cache_key in self._route_lookup:
            return self._route_lookup[cache_key]

        # Try to match against registered routes
        app = request.app
        routes = getattr(app, "routes", [])
        for route in routes:
            match, scope = route.matches({"type": "http", "method": request.method, "path": path})
            if match == Match.FULL:
                route_path = getattr(route, "path", path)
                template = _normalize_path(route_path)
                if len(self._seen_routes) < _MAX_ROUTE_TEMPLATES:
                    self._seen_routes.add(template)
                    self._route_lookup[cache_key] = template
                else:
                    template = "__other__"
                return template

        # Fallback: normalize the raw path
        template = _normalize_path(path)
        if len(self._seen_routes) < _MAX_ROUTE_TEMPLATES:
            self._seen_routes.add(template)
            self._route_lookup[cache_key] = template
        else:
            template = "__other__"
        return template

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        method = request.method
        route = self._resolve_route(request)

        start = time.monotonic()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception:
            status_code = 500
            raise
        finally:
            duration = time.monotonic() - start
            status_label = str(status_code)
            status_class = f"{status_code // 100}xx"

            try:
                from src.infrastructure.observability.metrics import get_metrics

                metrics = get_metrics()

                # Per-endpoint latency histogram
                metrics.histogram(
                    "http_request_duration_seconds",
                    "HTTP request latency in seconds by method, route, and status",
                    buckets=_HTTP_LATENCY_BUCKETS,
                    labels={"method": method, "route": route, "status": status_label},
                ).observe(duration)

                # Request rate counter
                metrics.counter(
                    "http_requests_total",
                    "Total HTTP requests by method, route, and status",
                    labels={"method": method, "route": route, "status": status_label},
                ).inc()

                # Error rate counter (by status class for cardinality control)
                if status_code >= 400:
                    metrics.counter(
                        "http_request_errors_total",
                        "Total HTTP error requests by method, route, and status class",
                        labels={"method": method, "route": route, "status_class": status_class},
                    ).inc()

                # In-flight gauge
                metrics.gauge(
                    "http_requests_in_flight",
                    "Number of HTTP requests currently being processed",
                    labels={"method": method},
                )
            except Exception:
                pass
