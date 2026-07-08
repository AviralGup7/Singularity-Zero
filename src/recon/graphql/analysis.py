"""GraphQL attack surface analysis functions."""

from __future__ import annotations

import json
import logging
from typing import Any

import requests

from src.recon.graphql.schema import (
    _ALIAS_TOKENS,
    _CSRF_COOKIE_NAMES,
    _GRAPHQL_WS_PROTOCOLS,
)

logger = logging.getLogger(__name__)


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


def _detect_graphql_ws(url: str, *, timeout_seconds: int = 5) -> list[str]:
    from urllib.parse import urlparse

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
                logger.debug("WebSocket protocol probe failed", exc_info=True)
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
        resp = requests.post(  # nosec
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
            resp = requests.post(  # nosec
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
        if data.get(candidate) is not None or data.get("__typename"):
            result["accessible_fields"].append(candidate)
        else:
            result["inaccessible_fields"].append(candidate)
    result["notes"] = "Anonymous-token field-level probe completed"
    return result
