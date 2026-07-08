"""Core GraphQL introspection functions."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import urlparse

import requests

from src.infrastructure.execution_engine.shared_pool import get_recon_executor
from src.recon.graphql.schema import (
    _INTROSPECTION_QUERY,
    _MAX_INTROSPECTION_BYTES,
    _PROBE_QUERY,
    _PROBE_TIMEOUT_SECONDS,
    _TYPENAME_NESTED_DEPTHS,
    GraphQLEndpoint,
)

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
        resp = requests.post(  # nosec
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


def _introspect_endpoint_sync(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_seconds: int = _PROBE_TIMEOUT_SECONDS,
    max_bytes: int = _MAX_INTROSPECTION_BYTES,
) -> GraphQLEndpoint:
    """Run a probe + introspection against a single GraphQL candidate URL."""
    from src.recon.graphql.analysis import (
        _alias_authorization_bypass,
        _check_apollo_persisted_query_headers,
        _detect_csrf_cookie_auth,
        _detect_graphql_ws,
        _probe_fields_for_auth_inference,
    )

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
        probe_resp = requests.post(  # nosec
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
        batch_resp = requests.post(  # nosec
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
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(
                    "Operation failed in graphql_introspection.py: %s", exc, exc_info=True
                )  # noqa: BLE001
    except requests.RequestException as exc:
        import logging

        logger = logging.getLogger(__name__)
        logger.warning("Operation failed in graphql_introspection.py: %s", exc, exc_info=True)  # noqa: BLE001
    if not batch_hit:
        endpoint.attack_surface["batching_amplification"] = {
            "detected": False,
            "notes": "JSON array batching not accepted",
        }

    # Phase 2: full introspection query.
    try:
        intro_resp = requests.post(  # nosec
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
    executor = get_recon_executor()
    return await loop.run_in_executor(
        executor,
        lambda: _introspect_endpoint_sync(
            url,
            headers=headers,
            timeout_seconds=timeout_seconds,
            max_bytes=max_bytes,
        ),
    )
