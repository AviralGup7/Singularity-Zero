"""GraphQL-over-WebSocket subscription message-injection probe.

Targets ``ws://`` / ``wss://`` URLs that look like GraphQL subscription
endpoints (``/graphql``, ``/subscriptions``, ``graphql-ws``,
``graphql-transport-ws`` subprotocols). Sends protocol messages in
the order defined by the two common subprotocols:

* ``graphql-ws``        (legacy, apollographql/subscriptions-transport-ws)
* ``graphql-transport-ws``  (current, recommendations from the GraphQL
  over WS working group)

For each subprotocol we attempt:

1. ``connection_init`` with no payload (or an empty ``Authorization``)
   - the server should reject unauthenticated connections when the
     endpoint is supposed to be auth-gated.
2. ``connection_ack`` -> the server confirms the connection.
3. ``subscribe`` with a probe subscription that targets the introspection
   schema (``subscription { __typename }``) or attempts to call a
   privileged field that an unauthenticated client should not be able
   to subscribe to.
4. Read whatever the server sends back.  Any ``next`` / ``data`` frame
   is evidence the subscription is reachable cross-origin / unauth.

Findings are returned in the same shape used by the rest of the active
probes so the coordinator can merge them into the same risk pipeline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


_GRAPHQL_WS_SUBPROTOCOLS = (
    "graphql-transport-ws",
    "graphql-ws",
)

# Probes sent after a successful connection_ack. Each is a (label, payload)
# tuple. The "introspection" probe is read-only and safe. The "me" probe
# assumes the server has a `me` field and is meant to confirm authorization
# is being enforced.
_PROBE_MESSAGES: tuple[tuple[str, dict[str, Any]], ...] = (
    (
        "introspection",
        {
            "id": "probe-introspection",
            "type": "subscribe",
            "payload": {
                "query": "subscription { __typename }",
            },
        },
    ),
    (
        "me_no_auth",
        {
            "id": "probe-me",
            "type": "subscribe",
            "payload": {
                "query": "subscription { me { id email } }",
            },
        },
    ),
)


def _is_graphql_ws_candidate(url: str) -> bool:
    """Return True if ``url`` looks like a GraphQL WebSocket endpoint."""
    parsed = urlparse(url)
    if parsed.scheme not in ("ws", "wss"):
        return False
    path = parsed.path.lower()
    return any(
        marker in path
        for marker in (
            "/graphql",
            "/subscriptions",
            "/subscription",
            "/ws",
            "/socket",
            "/realtime",
        )
    )


def _to_ws_url(http_url: str) -> str | None:
    """Convert http(s)://.../graphql -> ws(s)://.../graphql."""
    parsed = urlparse(http_url)
    if parsed.scheme not in ("http", "https", "ws", "wss"):
        return None
    if parsed.scheme in ("ws", "wss"):
        return http_url
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return parsed._replace(scheme=scheme).geturl()


async def _probe_one_subprotocol(
    ws_url: str, subprotocol: str, *, origin: str | None, verify_tls: bool
) -> dict[str, Any]:
    """Open a single WS connection, run the probe sequence, return a result dict."""
    record: dict[str, Any] = {
        "ws_url": ws_url,
        "subprotocol": subprotocol,
        "origin": origin,
        "connection_accepted": False,
        "subscribe_responses": [],
        "data_leaked": False,
        "error": None,
    }

    ssl_ctx: ssl.SSLContext | None = None
    if ws_url.startswith("wss://") and not verify_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    extra_headers: list[tuple[str, str]] = []
    if origin is not None:
        extra_headers.append(("Origin", origin))

    try:
        import websockets  # type: ignore[import-not-found]

        async with websockets.connect(
            ws_url,
            subprotocols=[subprotocol],
            ssl=ssl_ctx,
            additional_headers=extra_headers or None,
            open_timeout=5.0,
            close_timeout=2.0,
            max_size=2**16,
        ) as ws:
            # 1. connection_init
            await ws.send(json.dumps({"type": "connection_init", "payload": {}}))
            try:
                ack_raw = await asyncio.wait_for(ws.recv(), timeout=4.0)
            except (asyncio.TimeoutError, TimeoutError):
                record["error"] = "no_connection_ack"
                return record
            try:
                ack = json.loads(ack_raw)
            except (ValueError, TypeError):
                ack = {"raw": ack_raw[:200]}
            if str(ack.get("type", "")).lower() != "connection_ack":
                # graphql-transport-ws may send connection_error instead.
                record["error"] = f"ack_type={ack.get('type')!r}"
                return record
            record["connection_accepted"] = True

            # 2. fire each subscription probe and read the first response
            for label, message in _PROBE_MESSAGES:
                await ws.send(json.dumps(message))
                try:
                    response_raw = await asyncio.wait_for(ws.recv(), timeout=4.0)
                except (asyncio.TimeoutError, TimeoutError):
                    record["subscribe_responses"].append(
                        {"probe": label, "status": "no_response"}
                    )
                    continue
                try:
                    response = json.loads(response_raw)
                except (ValueError, TypeError):
                    response = {"raw": response_raw[:200] if hasattr(response_raw, "__getitem__") else str(response_raw)[:200]}
                rtype = str(response.get("type", "")).lower()
                entry: dict[str, Any] = {"probe": label, "type": rtype}
                if rtype in ("next", "data"):
                    payload = response.get("payload") or {}
                    data = payload.get("data") if isinstance(payload, dict) else None
                    errors = payload.get("errors") if isinstance(payload, dict) else None
                    entry["data_keys"] = list(data.keys()) if isinstance(data, dict) else []
                    if isinstance(data, dict) and data:
                        record["data_leaked"] = True
                    entry["errors"] = errors
                elif rtype == "error":
                    entry["error_payload"] = response.get("payload")
                record["subscribe_responses"].append(entry)
    except Exception as exc:  # noqa: BLE001 - any transport failure is a probe signal
        record["error"] = f"{type(exc).__name__}: {exc}"
    return record


async def _probe_url(
    ws_url: str, *, origin: str | None, verify_tls: bool
) -> dict[str, Any]:
    """Run both subprotocols against a single URL and merge results."""
    out: dict[str, Any] = {
        "ws_url": ws_url,
        "origin": origin,
        "subprotocols": {},
        "connection_accepted": False,
        "data_leaked": False,
    }
    for subproto in _GRAPHQL_WS_SUBPROTOCOLS:
        result = await _probe_one_subprotocol(
            ws_url, subproto, origin=origin, verify_tls=verify_tls
        )
        out["subprotocols"][subproto] = result
        if result.get("connection_accepted"):
            out["connection_accepted"] = True
        if result.get("data_leaked"):
            out["data_leaked"] = True
    return out


def graphql_ws_injection_probe(
    priority_urls: list[dict[str, Any]] | list[str],
    *,
    limit: int = 6,
    origins: list[str] | None = None,
    verify_tls: bool = False,
) -> list[dict[str, Any]]:
    """Active probe for GraphQL WebSocket subscription message-injection.

    For each candidate URL, attempts a graphql-ws and graphql-transport-ws
    connection WITHOUT authentication, then fires two read-only
    subscription probes. The two origins exercised are the configured
    list (defaults to the probe's own host and a known evil host) so we
    can spot cross-origin / CSWSH-style subscription abuse.

    Args:
        priority_urls: list of URL dicts (with a ``url`` key) or strings.
        limit: maximum number of findings to return.
        origins: optional override for the origins to test as ``Origin``
            header values. ``None`` means "use the default evil + same-host
            list".
        verify_tls: whether to validate TLS certificates against the
            websocket connection. Defaults to ``False`` to mirror the
            permissive posture of other active probes.

    Returns:
        List of finding dicts. Each finding contains the URL, the
        per-subprotocol results, and the corresponding issue labels.
    """
    origins = origins or [None, "https://evil.example.com", "null"]

    candidates: list[str] = []
    for entry in priority_urls:
        if isinstance(entry, dict):
            url = str(entry.get("url", ""))
        else:
            url = str(entry)
        url = url.strip()
        if not url:
            continue
        # Accept explicit ws:// candidates as-is, otherwise derive ws:// from http(s)
        if url.startswith(("ws://", "wss://")):
            candidates.append(url)
        else:
            ws_url = _to_ws_url(url)
            if ws_url:
                candidates.append(ws_url)

    # De-duplicate while preserving order
    seen: set[str] = set()
    unique_candidates: list[str] = []
    for u in candidates:
        if u in seen:
            continue
        if not _is_graphql_ws_candidate(u):
            continue
        seen.add(u)
        unique_candidates.append(u)

    findings: list[dict[str, Any]] = []
    for ws_url in unique_candidates:
        if len(findings) >= limit:
            break
        per_origin_results: list[dict[str, Any]] = []
        for origin in origins:
            try:
                result = asyncio.run(
                    _probe_url(ws_url, origin=origin, verify_tls=verify_tls)
                )
            except RuntimeError:
                # We're inside a running event loop; fall back to per-coroutine
                # execution. Should not happen for sync probe entry points.
                result = {
                    "ws_url": ws_url,
                    "origin": origin,
                    "error": "event_loop_already_running",
                }
            per_origin_results.append(result)

        issues: list[str] = []
        # A connection that is accepted without an Authorization payload
        # AND we successfully read subscription data -> high-confidence
        # finding.
        for r in per_origin_results:
            if r.get("data_leaked"):
                issues.append("graphql_ws_subscription_data_leaked")
                break
        for r in per_origin_results:
            if r.get("connection_accepted") and not r.get("data_leaked"):
                issues.append("graphql_ws_unauthenticated_subscription")
                break
        # Cross-origin subscription acceptance: same-host rejected but
        # evil-host accepted (or vice versa) -> CSWSH.
        hosts_accepting = {
            r.get("origin"): r
            for r in per_origin_results
            if r.get("connection_accepted")
        }
        if (
            len(hosts_accepting) > 1
            and None in hosts_accepting
            and any(
                origin is not None
                and "evil" in str(origin).lower()
                for origin in hosts_accepting
            )
        ):
            issues.append("graphql_ws_csws_origin_bypass")

        if not issues:
            continue

        findings.append(
            {
                "url": ws_url,
                "endpoint_key": ws_url,
                "endpoint_base_key": ws_url.split("?", 1)[0],
                "endpoint_type": "WebSocket",
                "issues": issues,
                "probe_type": "graphql_ws_subscription_injection",
                "per_origin_results": per_origin_results,
                "severity": (
                    "critical"
                    if "graphql_ws_subscription_data_leaked" in issues
                    else "high"
                    if "graphql_ws_unauthenticated_subscription" in issues
                    else "high"
                ),
                "confidence": 0.85
                if "graphql_ws_subscription_data_leaked" in issues
                else 0.7,
            }
        )

    findings.sort(key=lambda f: (-len(f.get("issues", [])), f.get("url", "")))
    return findings
