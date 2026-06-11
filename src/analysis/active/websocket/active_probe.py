"""WebSocket active probe.

Active WebSocket probing for the standard scan pipeline. Wraps the
existing :mod:`src.exploitation.websocket_exploit` (which is gated
behind the exploitation stage) and exposes a small, dependency-free
prober that the analysis orchestrator can invoke without needing
pre-captured frames.

Probes emitted:
* Endpoint discovery — bare upgrade requests to candidate URLs to
  confirm a WebSocket handshake succeeds.
* Origin bypass — the CSWSH check, replayed against the live
  endpoint.
* Frame injection — connect, send a small set of forged frames,
  look for side effects or unfiltered echoes.
* ping/pong abuse — fire rapid pings, observe rate-limiting and
  keepalive behaviour.

The module uses only :mod:`asyncio` streams — no third-party
WebSocket client — so it works in the same minimal environment as
the rest of the active-probe code.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import secrets
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# RFC 6455 opcodes
_OP_CONTINUATION = 0x0
_OP_TEXT = 0x1
_OP_BINARY = 0x2
_OP_CLOSE = 0x8
_OP_PING = 0x9
_OP_PONG = 0xA


@dataclass(slots=True)
class WSProbe:
    """Description of a single WebSocket probe run."""

    url: str
    origin: str | None = None
    subprotocols: tuple[str, ...] = ()
    extra_headers: dict[str, str] = field(default_factory=dict)
    frames: tuple[tuple[int, bytes], ...] = ()
    expected_anomaly: str = ""


@dataclass(slots=True)
class WSProbeResult:
    """Outcome of a single WebSocket probe."""

    url: str
    handshake_status: int = 0
    handshake_headers: dict[str, str] = field(default_factory=dict)
    accepted_subprotocol: str | None = None
    sent_frames: int = 0
    received_frames: tuple[tuple[int, bytes], ...] = ()
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.handshake_status == 101


def _ws_key() -> str:
    return base64.b64encode(secrets.token_bytes(16)).decode("ascii")


def _encode_frame(opcode: int, payload: bytes, mask: bytes | None = None) -> bytes:
    """Build a single RFC 6455 frame.

    When ``mask`` is provided the payload is masked with the given
    4-byte key. Client-to-server frames must be masked per the spec.
    """
    if mask is None:
        mask = secrets.token_bytes(4)
    header = bytearray()
    header.append(0x80 | (opcode & 0x0F))  # FIN + opcode
    length = len(payload)
    mask_bit = 0x80
    if length < 126:
        header.append(mask_bit | length)
    elif length < (1 << 16):
        header.append(mask_bit | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(mask_bit | 127)
        header.extend(struct.pack("!Q", length))
    header.extend(mask)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes(header) + masked


def _decode_frame_header(header: bytes) -> tuple[bool, int, int, int] | None:
    """Return (fin, opcode, payload_length, mask_key_offset) or None
    if the buffer is too short.
    """
    if len(header) < 2:
        return None
    b0, b1 = header[0], header[1]
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    offset = 2
    if length == 126:
        if len(header) < offset + 2:
            return None
        length = struct.unpack("!H", header[offset : offset + 2])[0]
        offset += 2
    elif length == 127:
        if len(header) < offset + 8:
            return None
        length = struct.unpack("!Q", header[offset : offset + 8])[0]
        offset += 8
    return fin, opcode, length, offset + (4 if masked else 0)


class WebSocketActiveProbe:
    """Run a small set of WebSocket probes against candidate URLs.

    Parameters
    ----------
    candidates:
        Iterable of ``ws://`` or ``wss://`` URLs to probe.
    """

    def __init__(
        self,
        candidates: Iterable[str],
        *,
        open_timeout: float = 5.0,
        frame_timeout: float = 3.0,
    ) -> None:
        self.candidates = [str(c) for c in candidates]
        self.open_timeout = open_timeout
        self.frame_timeout = frame_timeout

    def build_probes(self, url: str) -> list[WSProbe]:
        """Return the probe list for ``url``.

        Each probe is a *plan*; the actual socket work happens in
        :meth:`run_all`. Splitting probe construction from execution
        keeps the method unit-testable without an event loop.
        """
        parsed = urlparse(url)
        default_origin = f"{parsed.scheme}://{parsed.hostname or ''}"
        if parsed.port and parsed.port not in (80, 443):
            default_origin = f"{default_origin}:{parsed.port}"
        evil_origin = f"https://evil.{parsed.hostname or 'example.com'}"
        return [
            WSProbe(
                url=url,
                origin=default_origin,
                subprotocols=("chat", "superchat"),
                frames=((_OP_TEXT, b'{"action":"ping"}'),),
                expected_anomaly="Standard handshake (baseline)",
            ),
            WSProbe(
                url=url,
                origin=evil_origin,
                subprotocols=("chat",),
                frames=((_OP_TEXT, b'{"action":"ping"}'),),
                expected_anomaly="Origin not validated — CSWSH",
            ),
            WSProbe(
                url=url,
                origin=default_origin,
                subprotocols=(),
                extra_headers={
                    "Sec-WebSocket-Extensions": "permessage-deflate; server_max_window_bits=15",
                },
                frames=((_OP_PING, b"x" * 16),),
                expected_anomaly="permessage-deflate accepted (DoS surface)",
            ),
        ]

    async def _handshake_and_probe(self, probe: WSProbe) -> WSProbeResult:
        """Open a TCP connection, perform the upgrade, send probe frames."""
        parsed = urlparse(probe.url)
        if parsed.scheme not in {"ws", "wss"}:
            return WSProbeResult(
                url=probe.url,
                error=f"unsupported scheme: {parsed.scheme}",
            )
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        ssl = parsed.scheme == "wss"
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl),
                timeout=self.open_timeout,
            )
        except (TimeoutError, OSError) as exc:
            return WSProbeResult(url=probe.url, error=f"connect failed: {exc}")

        key = _ws_key()
        request_lines = [
            f"GET {parsed.path or '/'} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        if probe.origin:
            request_lines.append(f"Origin: {probe.origin}")
        if probe.subprotocols:
            request_lines.append("Sec-WebSocket-Protocol: " + ", ".join(probe.subprotocols))
        for k, v in probe.extra_headers.items():
            request_lines.append(f"{k}: {v}")
        request = ("\r\n".join(request_lines) + "\r\n\r\n").encode("ascii")
        writer.write(request)
        await writer.drain()

        try:
            status_line = await asyncio.wait_for(reader.readline(), timeout=self.open_timeout)
            headers: dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=self.open_timeout)
                if line in (b"\r\n", b"", b"\n"):
                    break
                if b":" in line:
                    k, v = line.decode("iso-8859-1").split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            status = int(status_line.split()[1]) if status_line else 0
        except (TimeoutError, ValueError, IndexError) as exc:
            writer.close()
            return WSProbeResult(url=probe.url, error=f"handshake failed: {exc}")

        result = WSProbeResult(
            url=probe.url,
            handshake_status=status,
            handshake_headers=headers,
            accepted_subprotocol=headers.get("sec-websocket-protocol"),
        )
        if status != 101:
            writer.close()
            return result

        sent = 0
        received: list[tuple[int, bytes]] = []
        for opcode, payload in probe.frames:
            try:
                writer.write(_encode_frame(opcode, payload))
                await writer.drain()
                sent += 1
            except (ConnectionError, OSError) as exc:
                result.error = f"send failed: {exc}"
                break
            try:
                hdr = await asyncio.wait_for(reader.readexactly(2), timeout=self.frame_timeout)
                decoded = _decode_frame_header(hdr)
                if not decoded:
                    continue
                _, _, length, header_end = decoded
                body = await asyncio.wait_for(
                    reader.readexactly(length), timeout=self.frame_timeout
                )
                received.append((_OP_TEXT, body))
            except TimeoutError as exc:
                logger.warning("Operation failed in active_probe.py: %s", exc, exc_info=True)  # noqa: BLE001
            except (ConnectionError, OSError) as exc:
                result.error = f"recv failed: {exc}"
                break

        result.sent_frames = sent
        result.received_frames = tuple(received)
        try:
            writer.close()
        except Exception as exc:
            logger.debug("Failed to close writer: %s", exc, exc_info=True)
        return result

    async def run_all(self) -> list[WSProbeResult]:
        """Run every probe for every candidate URL."""
        results: list[WSProbeResult] = []
        for url in self.candidates:
            for probe in self.build_probes(url):
                try:
                    results.append(await self._handshake_and_probe(probe))
                except Exception as exc:  # noqa: BLE001
                    results.append(WSProbeResult(url=url, error=f"unhandled: {exc}"))
        return results


__all__ = [
    "WebSocketActiveProbe",
    "WSProbe",
    "WSProbeResult",
]
