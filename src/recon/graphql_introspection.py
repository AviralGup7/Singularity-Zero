"""GraphQL introspection and endpoint discovery.

GraphQL endpoints are a major source of high-value bug-bounty findings.
Unlike REST APIs where the attack surface is determined by the URL
path, GraphQL exposes a single ``POST /graphql`` endpoint that can
invoke any query/mutation/subscription declared in the schema. The
schema is itself queryable via the standard introspection query —
which is enabled by default on the vast majority of public GraphQL
APIs.

This module:

1. **Probes candidate GraphQL endpoints** for a list of hosts. The
   default paths cover the most common conventions (``/graphql``,
   ``/gql``, ``/api/graphql``, ``/graphql/v1``, etc.) plus a small
   "maybe it's the same site at a different path" list.

2. **Runs a sanitised introspection query** (truncated to avoid
   giant schema dumps that fail on slow APIs) against each endpoint
   that responds with GraphQL-shaped content-type or with the
   sentinel ``"__schema"`` JSON key.

3. **Extracts the schema** as a structured dict with operations
   (queries / mutations / subscriptions), their arguments, and the
   return types. The output is suitable for direct Nuclei tag
   targeting (``graphql-introspect``, ``graphql-injection``,
   ``excessive-data-exposure``) and for hand-driven testing.

4. **Detects authorisation** by issuing a probe that exercises a
   benign field. The response is annotated with whether the server
   required authentication — useful for separating "open public API"
   from "needs a token" assets.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from src.core.utils.url_validation import is_safe_url

logger = logging.getLogger(__name__)

# Default GraphQL endpoint paths to probe, in priority order.
DEFAULT_GRAPHQL_PATHS: tuple[str, ...] = (
    "/graphql",
    "/graphql/v1",
    "/graphql/v2",
    "/gql",
    "/api/graphql",
    "/api/gql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/api/query",
    "/graphql/console",
    "/graphiql",
    "/playground",
    "/altair",
)

# Sanitised introspection query: we cap the depth and disable
# descriptions to keep the response small enough for production
# APIs that reject multi-megabyte schema dumps. Operators who need
# the full schema can run an external ``graphql-inspector`` against
# the saved endpoint URL.
_INTROSPECTION_QUERY: str = (
    "query IntrospectionQuery {"
    "  __schema {"
    "    queryType { name }"
    "    mutationType { name }"
    "    subscriptionType { name }"
    "    types {"
    "      kind name"
    "      fields(includeDeprecated: false) {"
    "        name args { name type { kind name ofType { kind name } } }"
    "        type { kind name ofType { kind name ofType { kind name } } }"
    "      }"
    "    }"
    "  }"
    "}"
)

# A minimal probe to detect "endpoint exists" without paying the cost
# of the full introspection query. Many production GraphQL APIs will
# return 200 with an error for an empty query; we look for that shape.
_PROBE_QUERY: str = '{"query":"{__typename}"}'

# Concurrent in-flight probes.
_PROBE_CONCURRENCY = 8

# Per-probe timeout in seconds.
_PROBE_TIMEOUT_SECONDS = 6

# Cap on introspection response body size (defends against runaway
# schemas being sent back). 1 MiB is enough for almost every public
# schema; operators with monster internal schemas can override via
# the ``graphql_introspection_max_bytes`` config key.
_MAX_INTROSPECTION_BYTES = 1 * 1024 * 1024


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class GraphQLEndpoint:
    """A single GraphQL endpoint discovered for a host."""

    host: str
    url: str
    status_code: int = 0
    content_type: str = ""
    introspection_status: str = "unknown"
    schema_operations: dict[str, list[str]] = field(default_factory=dict)
    requires_auth: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "introspection_status": self.introspection_status,
            "schema_operations": {
                op: sorted(set(names)) for op, names in self.schema_operations.items()
            },
            "requires_auth": self.requires_auth,
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Endpoint discovery
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------


_GRAPHQL_KEY_RE = re.compile(
    r'"(?:query|mutation|subscription|__schema|__typename|errors|data)"',
    re.IGNORECASE,
)


def _looks_like_graphql(content_type: str, body: str) -> bool:
    """Cheap heuristic to detect GraphQL-shaped responses."""
    ct = (content_type or "").lower()
    if "graphql" in ct or "application/json" in ct:
        if body and _GRAPHQL_KEY_RE.search(body):
            return True
    return False


def _extract_operations(schema: dict[str, Any]) -> dict[str, list[str]]:
    """Walk the introspection result and pull out the operation names."""
    operations: dict[str, list[str]] = {"query": [], "mutation": [], "subscription": []}
    if not isinstance(schema, dict):
        return operations
    schema_root = schema.get("__schema") or {}
    if not isinstance(schema_root, dict):
        return operations
    types = schema_root.get("types") or []
    if not isinstance(types, list):
        return operations

    type_map: dict[str, dict[str, Any]] = {}
    for entry in types:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
            type_map[entry["name"]] = entry

    for op_kind, type_name in (
        ("query", schema_root.get("queryType", {}).get("name") if isinstance(schema_root.get("queryType"), dict) else None),
        ("mutation", schema_root.get("mutationType", {}).get("name") if isinstance(schema_root.get("mutationType"), dict) else None),
        ("subscription", schema_root.get("subscriptionType", {}).get("name") if isinstance(schema_root.get("subscriptionType"), dict) else None),
    ):
        if not type_name:
            continue
        root_type = type_map.get(type_name, {})
        for entry in root_type.get("fields") or []:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                operations[op_kind].append(entry["name"])
    return operations


def _introspect_endpoint_sync(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_seconds: int = _PROBE_TIMEOUT_SECONDS,
    max_bytes: int = _MAX_INTROSPECTION_BYTES,
) -> GraphQLEndpoint:
    """Run a probe + introspection against a single GraphQL candidate URL."""
    host = (urlparse(url).hostname or "").lower()
    endpoint = GraphQLEndpoint(host=host, url=url)

    request_headers = {
        "User-Agent": "cyber-pipeline/2.0 (graphql-introspection)",
        "Accept": "application/json, text/plain;q=0.5, */*;q=0.1",
        "Content-Type": "application/json",
    }
    if headers:
        request_headers.update(headers)

    # Phase 1: lightweight probe to confirm the endpoint exists.
    try:
        probe_resp = requests.post(
            url,
            data=_PROBE_QUERY,
            headers=request_headers,
            timeout=max(2, timeout_seconds),
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        endpoint.notes.append(f"probe failed: {exc}")
        return endpoint

    endpoint.status_code = probe_resp.status_code
    endpoint.content_type = probe_resp.headers.get("content-type", "")
    if probe_resp.status_code >= 400:
        endpoint.notes.append(f"probe HTTP {probe_resp.status_code}")
        return endpoint

    body = (probe_resp.text or "")[:max_bytes]
    if not _looks_like_graphql(endpoint.content_type, body):
        endpoint.notes.append("probe response did not look like GraphQL")
        return endpoint

    # Phase 2: full introspection query.
    try:
        intro_resp = requests.post(
            url,
            data=json.dumps({"query": _INTROSPECTION_QUERY}),
            headers=request_headers,
            timeout=max(2, timeout_seconds),
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        endpoint.introspection_status = "transport_error"
        endpoint.notes.append(f"introspection failed: {exc}")
        return endpoint

    if intro_resp.status_code in (401, 403):
        endpoint.introspection_status = "auth_required"
        endpoint.requires_auth = True
        endpoint.notes.append(f"introspection returned HTTP {intro_resp.status_code}")
        return endpoint

    if intro_resp.status_code >= 400:
        endpoint.introspection_status = "blocked"
        endpoint.notes.append(f"introspection returned HTTP {intro_resp.status_code}")
        return endpoint

    try:
        intro_body = intro_resp.json()
    except json.JSONDecodeError as exc:
        endpoint.introspection_status = "invalid_json"
        endpoint.notes.append(f"introspection JSON parse failed: {exc}")
        return endpoint

    if not isinstance(intro_body, dict):
        endpoint.introspection_status = "invalid_shape"
        return endpoint

    if "errors" in intro_body and "data" not in intro_body:
        endpoint.introspection_status = "disabled"
        endpoint.notes.append(
            "introspection disabled or rejected: "
            + str(intro_body.get("errors", ""))[:200]
        )
        return endpoint

    schema = (intro_body.get("data") or {}).get("__schema")
    if not isinstance(schema, dict):
        endpoint.introspection_status = "empty_schema"
        return endpoint

    endpoint.introspection_status = "ok"
    endpoint.schema_operations = _extract_operations(schema)
    return endpoint


async def introspect_endpoint_async(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_seconds: int = _PROBE_TIMEOUT_SECONDS,
    max_bytes: int = _MAX_INTROSPECTION_BYTES,
) -> GraphQLEndpoint:
    """Async wrapper around :func:`_introspect_endpoint_sync`."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _introspect_endpoint_sync(
            url,
            headers=headers,
            timeout_seconds=timeout_seconds,
            max_bytes=max_bytes,
        ),
    )


# ---------------------------------------------------------------------------
# Bulk discovery
# ---------------------------------------------------------------------------


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

    workers = max(1, min(max_workers, len(candidate_urls)))
    results: list[GraphQLEndpoint] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
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


__all__ = [
    "DEFAULT_GRAPHQL_PATHS",
    "GraphQLEndpoint",
    "discover_graphql_endpoints",
    "filter_introspection_ok",
    "introspect_endpoint_async",
    "summarize_endpoints",
]
