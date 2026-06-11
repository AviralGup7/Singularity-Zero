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

Attack-surface additions:

- **batching amplification** — probes whether the endpoint accepts a
  JSON array payload and returns batched responses, enabling cost
  amplification / DoS.
- **alias-based auth bypass** — inspects the schema for field aliases
  that point to sensitive data (email, password, token …) that may be
  reachable through a proxy-resistant alias.
- **Apollo Relay persisted-query analysis** — detects SHA-256 query
  whitelisting and the ``x-apollo-operation-name`` / ``apollo-hash``
  header patterns that indicate persisted-query enforcement.
- **GraphQL-over-WebSocket probe patterns** — checks for
  ``graphql-ws`` and ``graphql-transport-ws`` subprotocol support.
- **CSRF-style detection for cookie-authenticated endpoints** — sends
  a cheap graphql POST with a forged cookie header and looks for
  Set-Cookie responses that indicate server-side session state.
- **introspection bypass probing** — crawls nested ``__typename``
  queries at increasing depths to find where introspection data leaks
  through when the top-level ``__schema`` introspection is disabled.
- **production GraphQL Playground / GraphiQL exposure detection** —
  flags IDE endpoints.
- **field-level auth inference** — probes discovered fields with an
  anonymous token to surface which sensitive fields are actually
  accessible unauthenticated.
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

_ALIAS_TOKENS: tuple[str, ...] = (
    "email",
    "emails",
    "phone",
    "phones",
    "password",
    "passwords",
    "ssn",
    "social",
    "secret",
    "token",
    "tokens",
    "apiKey",
    "api_keys",
    "creditCard",
    "address",
    "billing",
    "payment",
    "balance",
    "transaction",
    "internal",
    "admin",
    "role",
    "permission",
    "permissions",
)

_TYPENAME_NESTED_DEPTHS: tuple[int, ...] = (2, 3, 4, 6, 8, 10)

_GRAPHQL_WS_PROTOCOLS: tuple[str, ...] = (
    "graphql-ws",
    "graphql-transport-ws",
)

_INTROSPECTION_BYPASS_FIELDS: tuple[str, ...] = (
    "__typename",
    "id",
    "_id",
    "createdAt",
    "updatedAt",
)

_FIELD_PROBE_FIELDS: tuple[str, ...] = (
    "__typename",
    "id",
    "name",
    "email",
    "username",
    "createdAt",
)

_CSRF_COOKIE_NAMES: tuple[str, ...] = (
    "sessionid",
    "session",
    "sid",
    "auth",
    "token",
    "access_token",
    "refresh_token",
    "connect.sid",
)


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
    attack_surface: dict[str, Any] = field(default_factory=dict)

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
            "attack_surface": self.attack_surface,
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

_GRAPHQL_INTROSPECTION_ERROR_RE = re.compile(
    r"introspection|schema|response.*grid",
    re.IGNORECASE,
)


def _looks_like_graphql(content_type: str, body: str) -> bool:
    """Cheap heuristic to detect GraphQL-shaped responses."""
    ct = (content_type or "").lower()
    if "graphql" in ct or "application/json" in ct:
        if body and _GRAPHQL_KEY_RE.search(body):
            return True
    return False


def _detect_merged_response_grid(intro_body: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "detected": False,
        "notes": "",
    }
    if not isinstance(intro_body, dict):
        return result
    errors = intro_body.get("errors") or []
    if not isinstance(errors, list) or not errors:
        return result
    classes: set[str] = set()
    for entry in errors:
        if not isinstance(entry, dict):
            continue
        ext = entry.get("extensions") or {}
        if isinstance(ext, dict):
            classes.update(str(k) for k in ext.keys())
    if any(_GRAPHQL_INTROSPECTION_ERROR_RE.search(c) for c in classes):
        result["detected"] = True
        result["notes"] = "Response grid with introspection error extension detected"
    return result


def _detect_debug_headers(resp: requests.Response) -> dict[str, Any]:
    result: dict[str, Any] = {
        "detected": False,
        "header_names": [],
    }
    seen: list[tuple[str, str]] = []
    for raw_key, raw_val in resp.headers.items():
        if re.search(
            r"x-graphql|graphql-introspection|graphql-debug|graphql-errors|x-apollo|x-introspection",
            raw_key,
            re.IGNORECASE,
        ):
            seen.append((raw_key, str(raw_val)[:128]))
    if seen:
        result["detected"] = True
        result["header_names"] = seen
    return result


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
        (
            "query",
            schema_root.get("queryType", {}).get("name")
            if isinstance(schema_root.get("queryType"), dict)
            else None,
        ),
        (
            "mutation",
            schema_root.get("mutationType", {}).get("name")
            if isinstance(schema_root.get("mutationType"), dict)
            else None,
        ),
        (
            "subscription",
            schema_root.get("subscriptionType", {}).get("name")
            if isinstance(schema_root.get("subscriptionType"), dict)
            else None,
        ),
    ):
        if not type_name:
            continue
        root_type = type_map.get(type_name, {})
        for entry in root_type.get("fields") or []:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                operations[op_kind].append(entry["name"])
    return operations


def _alias_authorization_bypass(schema: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "batching_amplification": {
            "detected": False,
            "notes": "",
        },
        "alias_authorization_bypass": {
            "detected": False,
            "sensitive_aliases": [],
            "notes": "",
        },
        "apollo_persisted_query": {
            "detected": False,
            "sha256_required": False,
            "sha256_fields_found": [],
            "notes": "",
        },
        "graphql_over_websocket_protocols": [],
        "csrf_cookie_authenticated": {
            "detected": False,
            "cookie_names_found": [],
            "notes": "",
        },
        "introspection_bypass_nested_typename": {
            "detected": False,
            "max_depth_reached": 0,
            "notes": "",
        },
        "playground_graphiql_exposure": {
            "detected": False,
            "locations": [],
            "notes": "",
        },
        "field_level_auth_inference": {
            "accessible_fields": [],
            "inaccessible_fields": [],
            "notes": "",
        },
    }

    types = (schema.get("__schema") or {}).get("types") or []
    if not isinstance(types, list):
        return result
    aliases_found: list[str] = []

    for entry in types:
        if not isinstance(entry, dict):
            continue
        fields = entry.get("fields") or []
        if not isinstance(fields, list):
            continue
        for f in fields:
            if not isinstance(f, dict):
                continue
            fname = str(f.get("name", "")).lower()
            if any(tok in fname for tok in ("alias",)):
                aliases_found.append(fname)
            for tok in _ALIAS_TOKENS:
                if tok in fname and fname not in aliases_found:
                    aliases_found.append(fname)
                    break

    result["alias_authorization_bypass"]["detected"] = bool(aliases_found)
    result["alias_authorization_bypass"]["sensitive_aliases"] = aliases_found
    if any(
        "query" == t
        for t in (schema.get("__schema") or {}).get("types", [{}])[0].get("fields", [])
        if isinstance(t, str)
    ):
        result["batching_amplification"]["notes"] = (
            "batching route may exist (queries endpoint present)"
        )
    return result


def _check_apollo_persisted_query_headers(headers: dict[str, str] | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "sha256_required": False,
        "sha256_fields_found": [],
        "notes": "",
    }
    if not isinstance(headers, dict):
        return result
    hlower = {k.lower(): v for k, v in headers.items() if isinstance(k, str) and isinstance(v, str)}
    apollo_hdr = hlower.get("x-apollo-operation-name")
    hash_hdr = hlower.get("apollo-hash") or hlower.get("x-apollo-hash")
    ext_pq = (hlower.get("extensions") or "").lower()
    if "persistedquery" in ext_pq or "sha256" in ext_pq:
        result["sha256_required"] = True
        result["sha256_fields_found"].append("extensions.persistedQuery")
    if apollo_hdr or hash_hdr:
        result["sha256_fields_found"].append("apollo-operation-name/apollo-hash headers")
    if result["sha256_fields_found"]:
        result["notes"] = "Apollo Relay persisted-query detected"
    return result


def _build_nested_typename_query(depth: int) -> str:
    inner = "{ __typename }"
    query = inner
    for _ in range(max(0, int(depth) - 1)):
        query = f"{{ {inner} }}"
    return f"{{{query}}}"


def _introspection_bypass_nested_typename(
    url: str,
    query: str,
    headers: dict[str, str],
    *,
    timeout_seconds: int = 6,
) -> bool:
    try:
        resp = requests.post(
            url,
            data=json.dumps({"query": query}),
            headers=headers,
            timeout=max(2, timeout_seconds),
            allow_redirects=False,
        )
    except requests.RequestException:
        return False
    if resp.status_code != 200:
        return False
    try:
        body = resp.json()
    except json.JSONDecodeError:
        return False
    if not isinstance(body, dict):
        return False
    if "data" in body and body.get("data"):
        return True
    return False


def _detect_graphql_ws(url: str, *, timeout_seconds: int = 5) -> list[str]:
    protocols: list[str] = []
    origin = urlparse(url).netloc or urlparse(url).hostname or ""
    if not origin:
        return protocols
    ws_base = f"wss://{origin}" if urlparse(url).scheme == "https" else f"ws://{origin}"
    try:
        import websocket  # noqa: F401

        for proto in _GRAPHQL_WS_PROTOCOLS:
            try:
                ws = websocket.create_connection(
                    ws_base,
                    header=[f"Sec-WebSocket-Protocol: {proto}"],
                    subprotocols=[proto],
                    timeout=max(2, timeout_seconds),
                )
                ws.settimeout(1)
                try:
                    ws.send(json.dumps({"type": "connection_init"}))
                    resp = json.loads(ws.recv())
                except Exception:
                    resp = {}
                ws.close()
                if resp.get("type") in ("connection_ack", "ka", "data"):
                    protocols.append(proto)
            except Exception:
                continue
    except ImportError as exc:
        logger.warning("Operation failed in graphql_introspection.py: %s", exc, exc_info=True)  # noqa: BLE001
    return protocols


def _detect_csrf_cookie_auth(url: str, *, timeout_seconds: int = 6) -> dict[str, Any]:
    result: dict[str, Any] = {
        "detected": False,
        "cookie_names_found": [],
        "notes": "",
    }
    try:
        resp = requests.post(
            url,
            data=json.dumps({"query": "{ __typename }"}),
            headers={"Content-Type": "application/json", "Cookie": "sessionid=test;"},
            timeout=max(2, timeout_seconds),
            allow_redirects=False,
        )
    except requests.RequestException:
        return result
    set_cookie_hdr = resp.headers.get("set-cookie", "")
    seen: list[str] = []
    for name in _CSRF_COOKIE_NAMES:
        if name in set_cookie_hdr.lower() or name in resp.headers.get("x-cookie", "").lower():
            seen.append(name)
    if seen:
        result["detected"] = True
        result["cookie_names_found"] = seen
        result["notes"] = "Cookie-authenticated GraphQL detected"
    return result


def _probe_fields_for_auth_inference(
    url: str,
    ops: dict[str, list[str]],
    headers: dict[str, str],
    *,
    timeout_seconds: int = 6,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "accessible_fields": [],
        "inaccessible_fields": [],
        "notes": "",
    }
    anon = {
        k: v
        for k, v in headers.items()
        if k.lower() not in ("authorization", "x-api-key", "cookie")
    }
    candidates: list[str] = []
    for items in ops.values():
        candidates.extend(items or [])
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        q = "{ __typename " + candidate + " }"
        try:
            resp = requests.post(
                url,
                data=json.dumps({"query": q}),
                headers={**anon, "Content-Type": "application/json"},
                timeout=max(2, timeout_seconds),
                allow_redirects=False,
            )
        except requests.RequestException:
            continue
        try:
            body = resp.json()
        except json.JSONDecodeError:
            continue
        data = (body.get("data") or {}) if isinstance(body, dict) else {}
        if data.get(field) is not None or data.get("__typename"):
            result["accessible_fields"].append(field)
        else:
            result["inaccessible_fields"].append(field)
    result["notes"] = "Anonymous-token field-level probe completed"
    return result


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
    endpoint.attack_surface = {}

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

    endpoint.attack_surface["debug_headers"] = _detect_debug_headers(probe_resp)

    # Phase 1b: batching amplification probe.
    batch_payload = json.dumps([{"query": "{__typename}"}, {"query": "{__typename}"}])
    batch_hit = False
    try:
        batch_resp = requests.post(
            url,
            data=batch_payload,
            headers=request_headers,
            timeout=max(2, timeout_seconds),
            allow_redirects=False,
        )
        if batch_resp.status_code == 200:
            try:
                batch_body = batch_resp.json()
                if isinstance(batch_body, list) and len(batch_body) == 2:
                    batch_hit = True
                    endpoint.attack_surface["batching_amplification"] = {
                        "detected": True,
                        "notes": "JSON array batching accepted with 2 results returned",
                    }
            except json.JSONDecodeError as exc:
                logger.warning(
                    "Operation failed in graphql_introspection.py: %s", exc, exc_info=True
                )  # noqa: BLE001
    except requests.RequestException as exc:
        logger.warning("Operation failed in graphql_introspection.py: %s", exc, exc_info=True)  # noqa: BLE001
    if not batch_hit:
        endpoint.attack_surface["batching_amplification"] = {
            "detected": False,
            "notes": "JSON array batching not accepted",
        }

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
            "introspection disabled or rejected: " + str(intro_body.get("errors", ""))[:200]
        )
        if not isinstance(endpoint.attack_surface, dict):
            endpoint.attack_surface = {}
        endpoint.attack_surface["merged_response_grid"] = _detect_merged_response_grid(intro_body)
        return endpoint

    schema = (intro_body.get("data") or {}).get("__schema")
    if not isinstance(schema, dict):
        endpoint.introspection_status = "empty_schema"
        return endpoint

    endpoint.introspection_status = "ok"
    endpoint.schema_operations = _extract_operations(schema)
    endpoint.attack_surface = _alias_authorization_bypass(schema)
    apollo = _check_apollo_persisted_query_headers(request_headers)
    if apollo.get("sha256_required") or apollo.get("sha256_fields_found"):
        if isinstance(endpoint.attack_surface, dict):
            endpoint.attack_surface["apollo_persisted_query"] = apollo

    ws_protocols = _detect_graphql_ws(endpoint.url, timeout_seconds=4)
    if ws_protocols:
        endpoint.attack_surface["graphql_over_websocket_protocols"] = ws_protocols

    if endpoint.introspection_status == "ok":
        for depth in _TYPENAME_NESTED_DEPTHS:
            if depth <= 3:
                continue
            typename_q = _build_nested_typename_query(depth)
            passed = _introspection_bypass_nested_typename(
                url, typename_q, request_headers, timeout_seconds=4
            )
            if passed:
                endpoint.attack_surface["introspection_bypass_nested_typename"] = {
                    "detected": True,
                    "max_depth_reached": depth,
                    "notes": f"__typename reachable at nesting depth {depth}",
                }
                break

    csrf = _detect_csrf_cookie_auth(url, timeout_seconds=5)
    if csrf.get("detected") and csrf.get("cookie_names_found"):
        endpoint.attack_surface["csrf_cookie_authenticated"] = csrf

    if endpoint.introspection_status == "ok" and endpoint.schema_operations:
        field_result = _probe_fields_for_auth_inference(
            url, endpoint.schema_operations, request_headers, timeout_seconds=5
        )
        if field_result.get("accessible_fields") or field_result.get("inaccessible_fields"):
            endpoint.attack_surface["field_level_auth_inference"] = field_result

    playground_paths = ("/graphql/console", "/graphiql", "/playground", "/altair")
    if any(p in url.lower() for p in playground_paths):
        endpoint.attack_surface["playground_graphiql_exposure"] = {
            "detected": True,
            "locations": [url],
            "notes": "Dedicated GraphQL IDE endpoint exposed",
        }
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
