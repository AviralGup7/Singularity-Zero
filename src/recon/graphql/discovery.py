"""GraphQL URL construction and bulk discovery."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any
from urllib.parse import urljoin, urlparse

from src.core.utils.url_validation import is_safe_url
from src.infrastructure.execution_engine.shared_pool import get_recon_executor
from src.recon.graphql.introspection import _introspect_endpoint_sync
from src.recon.graphql.schema import (
    _PROBE_CONCURRENCY,
    _PROBE_TIMEOUT_SECONDS,
    DEFAULT_GRAPHQL_PATHS,
    GraphQLEndpoint,
)

logger = logging.getLogger(__name__)


def _normalize_base(host: str) -> str:
    host = (host or "").strip().lower()
    if not host:
        return ""
    if "://" in host:
        return host
    return f"https://{host}"


def _candidate_endpoint_urls(
    host: str,
    extra_paths: Iterable[str] | None = None,
) -> list[str]:
    """Build the absolute URL list to probe for a host."""
    base = _normalize_base(host)
    if not base or not is_safe_url(base):
        return []
    parsed = urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    paths = list(DEFAULT_GRAPHQL_PATHS)
    if extra_paths:
        paths.extend(p for p in extra_paths if p)
    urls: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if not path.startswith("/"):
            path = "/" + path
        url = urljoin(origin.rstrip("/") + "/", path.lstrip("/"))
        if url in seen:
            continue
        seen.add(url)
        if is_safe_url(url):
            urls.append(url)
    return urls


def discover_graphql_endpoints(
    hosts: Iterable[str],
    *,
    extra_paths: Iterable[str] | None = None,
    max_workers: int = _PROBE_CONCURRENCY,
    timeout_seconds: int = _PROBE_TIMEOUT_SECONDS,
    headers: dict[str, str] | None = None,
) -> list[GraphQLEndpoint]:
    """Run endpoint discovery + introspection across a list of hosts.

    Args:
        hosts: Hostnames or full URLs to probe.
        extra_paths: Additional relative paths to test beyond the
            built-in list.
        max_workers: Max concurrent probes.
        timeout_seconds: Per-probe timeout.
        headers: Optional HTTP headers (e.g. ``Authorization``).

    Returns:
        List of :class:`GraphQLEndpoint` for every candidate URL that
        responded with a GraphQL-shaped payload. Endpoints where the
        probe failed are still returned so the caller can decide to
        retry with a different path or auth header.
    """
    candidate_urls: list[tuple[str, str]] = []
    for host in hosts:
        for url in _candidate_endpoint_urls(host, extra_paths):
            candidate_urls.append((host, url))
    if not candidate_urls:
        return []

    results: list[GraphQLEndpoint] = []
    ex = get_recon_executor()
    futures = [
        ex.submit(
            _introspect_endpoint_sync,
            url,
            headers=headers,
            timeout_seconds=timeout_seconds,
        )
        for _, url in candidate_urls
    ]
    for fut in futures:
        try:
            results.append(fut.result())
        except Exception as exc:  # noqa: BLE001
            logger.debug("GraphQL probe failed: %s", exc)
    return results


# ---------------------------------------------------------------------------
# Convenience entry points
# ---------------------------------------------------------------------------


def filter_introspection_ok(
    endpoints: Iterable[GraphQLEndpoint],
) -> list[GraphQLEndpoint]:
    """Return only endpoints where introspection succeeded."""
    return [e for e in endpoints if e.introspection_status == "ok"]


def summarize_endpoints(endpoints: Iterable[GraphQLEndpoint]) -> dict[str, Any]:
    """Aggregate endpoint results into a JSON-serialisable summary."""
    endpoints_list = list(endpoints)
    return {
        "total": len(endpoints_list),
        "introspection_ok": sum(1 for e in endpoints_list if e.introspection_status == "ok"),
        "auth_required": sum(1 for e in endpoints_list if e.requires_auth),
        "introspection_disabled": sum(
            1 for e in endpoints_list if e.introspection_status == "disabled"
        ),
        "endpoints": [e.to_dict() for e in endpoints_list],
    }
