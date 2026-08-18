"""Coverage for previously untested WebSocket active-probe helpers."""

from __future__ import annotations

import struct

import pytest

from src.analysis.active.websocket.active_probe import (
    WebSocketActiveProbe,
    WSProbeResult,
    _decode_frame_header,
    _encode_frame,
    _ws_key,
)


@pytest.mark.unit
def test_ws_key_is_24_char_base64() -> None:
    key = _ws_key()
    assert len(key) == 24
    assert _ws_key() != key


@pytest.mark.unit
def test_encode_and_decode_small_text_frame() -> None:
    mask = b"\x01\x02\x03\x04"
    payload = b"ping"
    frame = _encode_frame(0x1, payload, mask=mask)
    decoded = _decode_frame_header(frame)
    assert decoded is not None
    fin, opcode, length, header_end = decoded
    assert fin is True
    assert opcode == 0x1
    assert length == 4
    assert frame[header_end - 4 : header_end] == mask
    masked = frame[header_end:]
    recovered = bytes(b ^ mask[i % 4] for i, b in enumerate(masked))
    assert recovered == payload


@pytest.mark.unit
def test_encode_medium_frame_uses_16bit_length() -> None:
    payload = b"x" * 200
    frame = _encode_frame(0x2, payload, mask=b"\x00\x00\x00\x00")
    decoded = _decode_frame_header(frame)
    assert decoded is not None
    _fin, opcode, length, _end = decoded
    assert opcode == 0x2
    assert length == 200
    assert frame[1] & 0x7F == 126
    assert struct.unpack("!H", frame[2:4])[0] == 200


@pytest.mark.unit
def test_decode_frame_header_too_short() -> None:
    assert _decode_frame_header(b"") is None
    assert _decode_frame_header(b"\x81") is None
    # 16-bit length advertised but missing the extra bytes
    assert _decode_frame_header(b"\x81\xfe") is None


@pytest.mark.unit
def test_ws_probe_result_ok_only_for_101() -> None:
    assert WSProbeResult(url="ws://x", handshake_status=101).ok is True
    assert WSProbeResult(url="ws://x", handshake_status=400).ok is False
    assert WSProbeResult(url="ws://x").ok is False


@pytest.mark.unit
def test_build_probes_covers_baseline_origin_bypass_and_deflate() -> None:
    probe = WebSocketActiveProbe(["ws://chat.example.com/socket"])
    plans = probe.build_probes("ws://chat.example.com/socket")
    assert len(plans) == 3
    origins = {p.origin for p in plans}
    assert "ws://chat.example.com" in origins
    assert any(p.origin and p.origin.startswith("https://evil.") for p in plans)
    assert any(
        "permessage-deflate" in p.extra_headers.get("Sec-WebSocket-Extensions", "") for p in plans
    )
    assert any("CSWSH" in p.expected_anomaly for p in plans)


@pytest.mark.unit
def test_build_probes_includes_non_default_port_in_origin() -> None:
    plans = WebSocketActiveProbe([]).build_probes("ws://localhost:9001/ws")
    assert any(p.origin == "ws://localhost:9001" for p in plans)
