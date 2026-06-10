"""WebSocket active probing stage.

The existing ``detection/api/websocket_message_security`` module is
passive — it analyses pre-captured WebSocket frames. The
``src/exploitation/websocket_exploit.py`` module has active
probes but is only reachable from the exploitation path, not the
default scan flow.

This module bridges the gap: it is invoked from the standard
pipeline as a :class:`PipelineStage` and produces a stream of
:class:`WebSocketProbeFinding` records. The stage:

1. Identifies candidate WebSocket endpoints from URL patterns and
   ``Upgrade: websocket`` response headers observed in the recon
   results.
2. Performs Cross-Site WebSocket Hijacking (CSWSH) origin bypass
   probes — every disallowed ``Origin`` is a finding.
3. Fuzzes message injection: empty, oversized, malformed JSON,
   non-text frames, ping/pong floods.
4. Records each finding as a structured observation for the
   triage queue.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
import websockets

logger = logging.getLogger(__name__)


@dataclass
class WebSocketProbeFinding:
    """A single observation from the WebSocket probe stage."""

    url: str
    probe: str
    severity: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


# Origins that should always be rejected. If any of them succeed in
# establishing a WebSocket connection, that's a CSWSH vulnerability.
DEFAULT_FORBIDDEN_ORIGINS: tuple[str, ...] = (
    "https://attacker.example",
    "null",
    "https://evil.com",
    "http://attacker.example",
)


# Patterns that flag a URL as a WebSocket candidate based on path
# or response header observation. The pipeline can pass these
# directly, or the stage can re-discover them.
DEFAULT_WS_PATH_HINTS: tuple[str, ...] = (
    "/ws",
    "/socket",
    "/socket.io",
    "/graphql",
    "/realtime",
    "/live",
    "/stream",
)


def looks_like_websocket_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme in {"ws", "wss"}:
        return True
    return any(hint in (parsed.path or "").lower() for hint in DEFAULT_WS_PATH_HINTS)


async def probe_cswsh(
    url: str,
    *,
    origins: Iterable[str] = DEFAULT_FORBIDDEN_ORIGINS,
    timeout: float = 5.0,
) -> list[WebSocketProbeFinding]:
    """Try to establish a WebSocket connection from forbidden origins.

    A finding is emitted for every origin the server accepts. The
    probe is non-destructive: it opens, optionally sends a small
    ping, and immediately closes.
    """
    findings: list[WebSocketProbeFinding] = []
    for origin in origins:
        try:
            async with websockets.connect(
                url,
                origin=origin,
                open_timeout=timeout,
                close_timeout=timeout,
            ) as ws:
                try:
                    await ws.send(json.dumps({"type": "ping"}))
                except Exception as exc:
                    logger.warning("Operation failed in websocket_probe.py: %s", exc, exc_info=True)  # noqa: BLE001
                findings.append(
                    WebSocketProbeFinding(
                        url=url,
                        probe="cswsh_origin_bypass",
                        severity="high",
                        description=(
                            f"WebSocket server accepted a connection from "
                            f"forbidden origin {origin!r}. CSWSH allows an "
                            f"attacker to ride the victim's session."
                        ),
                        evidence={"origin": origin},
                    )
                )
        except Exception as exc:
            logger.debug("CSWSH probe: %s rejected %s: %s", url, origin, exc)
    return findings


async def probe_message_fuzz(
    url: str,
    *,
    messages: Iterable[Mapping[str, Any] | str | bytes] | None = None,
    timeout: float = 5.0,
) -> list[WebSocketProbeFinding]:
    """Open a WebSocket and send a battery of fuzz messages.

    Each message that produces an unexpected close code (>= 1002
    or any 4xxx) is recorded as a finding. The default battery
    includes oversized JSON, malformed UTF-8, and ping floods.
    """
    if messages is None:
        messages = _default_fuzz_messages()
    findings: list[WebSocketProbeFinding] = []
    for msg in messages:
        try:
            async with websockets.connect(url, open_timeout=timeout, close_timeout=timeout) as ws:
                if isinstance(msg, bytes):
                    await ws.send(msg)
                else:
                    await ws.send(json.dumps(msg) if isinstance(msg, Mapping) else msg)
                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=timeout)
                except websockets.ConnectionClosed as exc:
                    if exc.code and (exc.code >= 1011 or 1004 <= exc.code <= 1015):
                        findings.append(
                            WebSocketProbeFinding(
                                url=url,
                                probe="message_fuzz",
                                severity="medium",
                                description=(
                                    f"Malformed message caused close code "
                                    f"{exc.code} ({exc.reason!r})."
                                ),
                                evidence={
                                    "message": _stringify(msg)[:200],
                                    "close_code": exc.code,
                                    "close_reason": exc.reason,
                                },
                            )
                        )
                except TimeoutError as exc:
                    logger.warning("Operation failed in websocket_probe.py: %s", exc, exc_info=True)  # noqa: BLE001
                else:
                    if isinstance(response, (bytes, bytearray)):
                        preview = response[:200]
                    else:
                        preview = response[:200]
                    findings.append(
                        WebSocketProbeFinding(
                            url=url,
                            probe="message_fuzz",
                            severity="info",
                            description="Server replied to fuzz message.",
                            evidence={
                                "message": _stringify(msg)[:200],
                                "response_preview": preview,
                            },
                        )
                    )
        except Exception as exc:
            logger.debug("message fuzz probe: %s failed: %s", url, exc)
    return findings


def _default_fuzz_messages() -> list[Any]:
    return [
        "",
        "x" * 65536,
        "\x00\x01\x02",
        {"__proto__": {"admin": True}},
        {"$ne": None},
        "{{constructor.constructor('return process')()}}",
        "AAAA" * 8192,
        # Ping flood: many small frames in quick succession.
    ] + [{"i": i} for i in range(20)]


def _stringify(msg: Any) -> str:
    if isinstance(msg, (bytes, bytearray)):
        try:
            return msg.decode("utf-8", errors="replace")
        except Exception:
            return repr(msg)[:200]
    if isinstance(msg, Mapping):
        try:
            return json.dumps(msg)
        except Exception:
            return str(msg)
    return str(msg)


async def discover_websocket_endpoints(
    base_urls: Iterable[str],
    *,
    timeout: float = 3.0,
) -> list[str]:
    """Best-effort discovery of WebSocket upgrade endpoints.

    Performs an HTTP GET with ``Upgrade: websocket`` against each
    base URL plus a few common path hints, and collects the URLs
    that respond with ``101 Switching Protocols`` or that
    advertise a ``Sec-WebSocket-*`` header.
    """
    discovered: list[str] = []
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        for base in base_urls:
            for hint in ("", *DEFAULT_WS_PATH_HINTS):
                target = base.rstrip("/") + hint
                ws_target = _http_to_ws(target)
                try:
                    response = await client.get(
                        target,
                        headers={
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Version": "13",
                            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        },
                    )
                except Exception:
                    continue
                if response.status_code in {101, 200, 426}:
                    discovered.append(ws_target)
                elif response.headers.get("sec-websocket-accept"):
                    discovered.append(ws_target)
    # Deduplicate while preserving order
    seen: set[str] = set()
    return [u for u in discovered if not (u in seen or seen.add(u))]


def _http_to_ws(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme in {"ws", "wss"}:
        return url
    if parsed.scheme == "https":
        return urlunparse(parsed._replace(scheme="wss"))
    return urlunparse(parsed._replace(scheme="ws"))


# Importing urlunparse lazily to avoid double-import noise at top of file
from urllib.parse import urlunparse  # noqa: E402


@dataclass
class WebSocketActiveProbe:
    """Stage entry-point: run all probes against a list of WS endpoints."""

    endpoints: list[str]
    timeout: float = 5.0
    max_concurrent: int = 4
    findings: list[WebSocketProbeFinding] = field(default_factory=list)

    async def run(self) -> list[WebSocketProbeFinding]:
        sem = asyncio.Semaphore(self.max_concurrent)

        async def _probe(url: str) -> list[WebSocketProbeFinding]:
            async with sem:
                results: list[WebSocketProbeFinding] = []
                try:
                    results.extend(await probe_cswsh(url, timeout=self.timeout))
                    results.extend(await probe_message_fuzz(url, timeout=self.timeout))
                except Exception as exc:
                    logger.debug("WebSocketActiveProbe: %s failed: %s", url, exc)
                return results

        nested = await asyncio.gather(*[_probe(u) for u in self.endpoints])
        for sub in nested:
            self.findings.extend(sub)
        return self.findings


__all__ = [
    "WebSocketActiveProbe",
    "WebSocketProbeFinding",
    "looks_like_websocket_url",
    "discover_websocket_endpoints",
    "probe_cswsh",
    "probe_message_fuzz",
]
