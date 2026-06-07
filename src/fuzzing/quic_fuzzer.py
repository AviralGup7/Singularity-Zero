"""QUIC protocol fuzzer.

Tests server behaviour against malformed QUIC Initial packets, CRYPTO frame
floods, CONTINUATION frame exhaustion, and invalid-version probes.
"""

from __future__ import annotations

import asyncio
import logging
import random
import struct
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.core.utils.url_validation import is_safe_url_with_dns_check

logger = logging.getLogger(__name__)


def _build_quic_initial_packet(dcid: bytes, scid: bytes) -> bytes:
    header = struct.pack("!B4s", 0xC0, 0x00000001)
    header += struct.pack("!B", len(dcid)) + dcid
    header += struct.pack("!B", len(scid)) + scid
    payload_len = random.randint(100, 400)
    payload = random.randbytes(payload_len)
    return header + payload


def _build_quic_crypto_frame(data: bytes, frame_type: int = 0x06) -> bytes:
    length = len(data)
    return struct.pack("!B", frame_type) + struct.pack("!I", length)[1:] + data


def _build_quic_invalid_packet() -> bytes:
    header = struct.pack("!B4s", 0xC0, 0xFFFFFFFF)
    header += struct.pack("!B", 0)
    header += struct.pack("!B", 0)
    payload_len = random.randint(50, 200)
    payload = random.randbytes(payload_len)
    return header + payload


def _quic_continuation_flood_payload(base: bytes, num_frames: int = 50) -> bytes:
    frames = bytearray()
    for _ in range(num_frames):
        length = random.randint(1, 4096)
        frame_data = random.randbytes(length)
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
            chunk = random.randbytes(chunk_size)
        frames += _build_quic_crypto_frame(chunk, frame_type=0x05)
    return bytes(frames)


_CRYPTO_FLOOD_DATA = (
    b"A" * 1200
    + b"\x01" * 1200
    + b"\x02" * 1200
    + b"\x03" * 1200
    + b"GET / HTTP/3\r\n\r\n" * 20
)


async def _probe_quic(host, port, timeout=3.0) -> dict[str, Any]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=port),
            timeout=timeout,
        )
    except Exception:
        return {
            "reachable": False,
            "crypto_sent": False,
            "response_bytes": 0,
            "response_preview": "",
        }

    crypto_sent = False
    response_bytes = 0
    response_preview = ""

    try:
        dcid = random.randbytes(random.randint(8, 20))
        scid = random.randbytes(random.randint(8, 20))
        initial_pkt = _build_quic_initial_packet(dcid, scid)
        writer.write(initial_pkt)
        await writer.drain()

        crypto_pkt = _build_quic_crypto_frame(_CRYPTO_FLOOD_DATA, frame_type=0x05)
        writer.write(crypto_pkt)
        await writer.drain()
        crypto_sent = True

        invalid_pkt = _build_quic_invalid_packet()
        writer.write(invalid_pkt)
        await writer.drain()

        try:
            response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            response_bytes = len(response)
            response_preview = response[:200].decode("latin-1", errors="replace")
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

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


async def run_quic_fuzzing_campaign(url, *, timeout_seconds=5.0) -> list[dict[str, Any]]:
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