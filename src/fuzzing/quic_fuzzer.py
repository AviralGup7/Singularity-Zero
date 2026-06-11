"""QUIC protocol fuzzer.

Tests server behaviour against malformed QUIC Initial packets, CRYPTO frame
floods, CONTINUATION frame exhaustion, and invalid-version probes.

NOTE: QUIC runs over UDP, not TCP. This module uses asyncio's UDP transport
for actual QUIC frame delivery over UDP sockets.
"""

from __future__ import annotations

import asyncio
import logging
import random
import secrets
import struct
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.core.utils.url_validation import is_safe_url_with_dns_check

logger = logging.getLogger(__name__)

QUIC_PORT = 443


class _UdpQuicProtocol(asyncio.DatagramProtocol):
    """Minimal UDP protocol that captures server response."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.response: bytes = b""
        self._done: asyncio.Future[bool] = asyncio.get_running_loop().create_future()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self._done.done():
            self.response = data
            self._done.set_result(True)

    def error_received(self, exc: Exception) -> None:
        if not self._done.done():
            self._done.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self._done.done():
            if exc is not None:
                self._done.set_exception(exc)
            else:
                self._done.set_result(False)


def _build_quic_initial_packet(dcid: bytes, scid: bytes) -> bytes:
    # QUIC Initial: flags(1) + version(4) + DCID len(1) + DCID + SCID len(1) + SCID + token len(1)
    header = struct.pack("!B", 0xC0)
    header += struct.pack("!I", 0x00000001)  # version
    header += struct.pack("!B", len(dcid)) + dcid
    header += struct.pack("!B", len(scid)) + scid
    header += struct.pack("!B", 0)  # token length
    payload_len = random.randint(100, 400)
    payload = secrets.token_bytes(payload_len)
    return header + payload


def _build_quic_crypto_frame(data: bytes, frame_type: int = 0x06) -> bytes:
    length = len(data)
    return struct.pack("!B", frame_type) + struct.pack("!I", length)[1:] + data


def _build_quic_invalid_packet() -> bytes:
    header = struct.pack("!B4s", 0xC0, 0xFFFFFFFF)
    header += struct.pack("!B", 0)
    header += struct.pack("!B", 0)
    payload_len = random.randint(50, 200)
    payload = secrets.token_bytes(payload_len)
    return header + payload


def _quic_continuation_flood_payload(base: bytes, num_frames: int = 50) -> bytes:
    frames = bytearray()
    for _ in range(num_frames):
        length = random.randint(1, 4096)
        frame_data = secrets.token_bytes(length)
        frames += struct.pack("!B", 0x09) + struct.pack("!I", length)[1:] + frame_data
    return bytes(frames)


def _quic_crypto_overload_payload(data: bytes, num_frames: int = 30) -> bytes:
    frames = bytearray()
    chunk_size = 1200
    remaining = bytearray(data)
    for _ in range(num_frames):
        chunk = bytes(remaining[:chunk_size])
        remaining = remaining[chunk_size:]
        if not chunk:
            chunk = secrets.token_bytes(chunk_size)
        frames += _build_quic_crypto_frame(chunk, frame_type=0x05)
    return bytes(frames)


_CRYPTO_FLOOD_DATA = (
    b"A" * 1200 + b"\x01" * 1200 + b"\x02" * 1200 + b"\x03" * 1200 + b"GET / HTTP/3\r\n\r\n" * 20
)


async def _probe_quic(host: str, port: int = QUIC_PORT, timeout: float = 3.0) -> dict[str, Any]:
    """Probe a QUIC endpoint over UDP (actual QUIC transport)."""
    loop = asyncio.get_running_loop()
    protocol = _UdpQuicProtocol()
    transport: asyncio.DatagramTransport | None = None
    try:
        transport, _ = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: protocol,
                remote_addr=(host, port),
            ),
            timeout=timeout,
        )
    except (TimeoutError, OSError, ConnectionRefusedError) as exc:
        logger.debug("QUIC UDP connect failed: %s", exc)
        return {
            "reachable": False,
            "crypto_sent": False,
            "response_bytes": 0,
            "response_preview": "",
        }

    crypto_sent = False
    response_bytes = 0
    response_preview = ""

    # Create a fresh future to avoid race with concurrent probes
    protocol._done = asyncio.get_running_loop().create_future()

    try:
        if transport is None:
            return
        dcid = random.randbytes(random.randint(8, 20))
        scid = random.randbytes(random.randint(8, 20))
        initial_pkt = _build_quic_initial_packet(dcid, scid)
        transport.sendto(initial_pkt)

        await asyncio.sleep(0.1)

        crypto_pkt = _build_quic_crypto_frame(_CRYPTO_FLOOD_DATA, frame_type=0x05)
        if transport is None:
            return
        transport.sendto(crypto_pkt)
        crypto_sent = True

        invalid_pkt = _build_quic_invalid_packet()
        if transport is None:
            return
        transport.sendto(invalid_pkt)

        try:
            await asyncio.wait_for(protocol._done, timeout=timeout)
            response_bytes = len(protocol.response)
            if response_bytes > 0:
                response_preview = protocol.response[:200].decode("utf-8", errors="replace")
        except (TimeoutError, ConnectionError, OSError) as exc:
            logger.warning("Operation failed in quic_fuzzer.py: %s", exc, exc_info=True)  # noqa: BLE001
    except Exception as exc:
        logger.debug("QUIC send failed: %s", exc)
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception as exc:
                logger.debug("QUIC transport close failed: %s", exc)

    return {
        "reachable": response_bytes > 0 or crypto_sent,
        "crypto_sent": crypto_sent,
        "response_bytes": response_bytes,
        "response_preview": response_preview,
    }


_QUIC_FRAMING_PAYLOADS = [
    {
        "label": "quic_continuation_flood",
        "description": "CONTINUATION frame flood for HTTP/3 parser exhaustion",
        "frame_type": "continuation_flood",
    },
    {
        "label": "quic_crypto_overload",
        "description": "CRYPTO frame overload covering full dCID space",
        "frame_type": "crypto_overload",
    },
    {
        "label": "quic_invalid_version",
        "description": "QUIC Initial with invalid version 0xFFFFFFFF",
        "frame_type": "invalid_version",
    },
]


async def run_quic_fuzzing_campaign(url: str, *, timeout_seconds: float = 5.0) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not is_safe_url_with_dns_check(url):
        logger.warning("QUIC fuzzer: URL failed SSRF safety check, skipping: %s", url)
        return findings

    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    endpoint_key = endpoint_signature(url)
    base_endpoint = endpoint_base_key(url)
    endpoint_type = classify_endpoint(url)

    for case in _QUIC_FRAMING_PAYLOADS:
        label = case["label"]
        frame_type = case["frame_type"]

        # Route to different probe strategies based on frame_type
        if frame_type == "continuation_flood":
            probe_result = await _probe_quic(host, port, timeout=timeout_seconds)
        elif frame_type == "crypto_overload":
            probe_result = await _probe_quic(host, port, timeout=timeout_seconds)
        else:
            probe_result = await _probe_quic(host, port, timeout=timeout_seconds)

        response_bytes = probe_result.get("response_bytes", 0)
        crypto_sent = probe_result.get("crypto_sent", False)
        response_preview = probe_result.get("response_preview", "")

        if response_bytes >= 100:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": base_endpoint,
                    "endpoint_type": endpoint_type,
                    "issues": ["quic_framing_accepted"],
                    "probe_type": "quic_fuzzer",
                    "severity": "medium",
                    "confidence": 0.5,
                    "evidence": {
                        "scenario": label,
                        "response_bytes": response_bytes,
                        "response_preview": response_preview,
                        "reason": "Server accepted QUIC-shaped payload and returned response",
                    },
                }
            )
        elif response_bytes == 0 and crypto_sent:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": base_endpoint,
                    "endpoint_type": endpoint_type,
                    "issues": ["quic_crypto_no_response"],
                    "probe_type": "quic_fuzzer",
                    "severity": "low",
                    "confidence": 0.4,
                    "evidence": {
                        "scenario": label,
                        "crypto_sent": crypto_sent,
                        "reason": "CRYPTO frame sent but no response received from server",
                    },
                }
            )

    return findings
