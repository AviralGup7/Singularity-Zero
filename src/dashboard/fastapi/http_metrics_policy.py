"""Policy helpers for optional HTTP metrics (no Starlette import)."""

from __future__ import annotations

import re

_HTTP_METRICS_TRUTHY = frozenset({"1", "true", "yes", "on"})

_PATH_NORMALIZERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), "{uuid}"),
    (re.compile(r"\d+"), "{id}"),
    (re.compile(r"[0-9a-f]{40}", re.I), "{sha}"),
    (re.compile(r"[0-9a-f]{64}", re.I), "{sha256}"),
]


def should_enable_http_metrics(value: str | None) -> bool:
    """Opt-in Prometheus HTTP metrics. Empty/unknown values stay off.

    RequestTimingMiddleware already records coarse latency. This more
    detailed per-route histogram is optional so both can coexist.
    """
    if value is None:
        return False
    return value.strip().lower() in _HTTP_METRICS_TRUTHY


def normalize_http_metrics_path(path: str) -> str:
    """Replace high-cardinality path segments with placeholders."""
    normalized = path
    for pattern, replacement in _PATH_NORMALIZERS:
        normalized = pattern.sub(replacement, normalized)
    return normalized
