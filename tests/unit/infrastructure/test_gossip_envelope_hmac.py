"""Regression: gossip parse_envelope must reject unsigned/tampered packets."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from src.infrastructure.mesh.gossip.serializer import make_envelope, parse_envelope, verify


@dataclass
class _Node:
    id: str
    host: str = "127.0.0.1"
    port: int = 9000


SECRET = b"mesh-shared-secret"
OTHER = b"attacker-secret"


@pytest.mark.unit
def test_signed_envelope_roundtrip_is_valid() -> None:
    raw = make_envelope(SECRET, _Node("n1"), "heartbeat", {"ok": True}, msg_id="n1-1")
    body, valid = parse_envelope(raw, SECRET)
    assert valid is True
    assert body["type"] == "heartbeat"
    assert body["payload"] == {"ok": True}
    assert body["msg_id"] == "n1-1"


@pytest.mark.unit
def test_unsigned_json_body_is_rejected() -> None:
    forged = b'{"body":{"type":"gossip","payload":{"pwn":true},"msg_id":"x"},"sig":""}'
    body, valid = parse_envelope(forged, SECRET)
    assert valid is False
    assert body is None


@pytest.mark.unit
def test_tampered_payload_fails_hmac() -> None:
    raw = make_envelope(
        SECRET, _Node("n1"), "gossip", {"leader_id": "n1"}, msg_id="n1-2", encrypt=False
    )
    tampered = raw.replace(b'"leader_id":"n1"', b'"leader_id":"evil"')
    body, valid = parse_envelope(tampered, SECRET)
    assert valid is False
    assert body is None


@pytest.mark.unit
def test_wrong_secret_is_rejected() -> None:
    raw = make_envelope(SECRET, _Node("n1"), "ack", {"ack_for": "m"}, msg_id="n1-3")
    body, valid = parse_envelope(raw, OTHER)
    assert valid is False
    assert body is None


@pytest.mark.unit
def test_missing_secret_never_marks_valid() -> None:
    raw = make_envelope(SECRET, _Node("n1"), "heartbeat", {}, msg_id="n1-4")
    body, valid = parse_envelope(raw)
    assert valid is False
    assert body is None


@pytest.mark.unit
def test_malformed_bytes_are_invalid() -> None:
    body, valid = parse_envelope(b"not-json", SECRET)
    assert valid is False
    assert body is None


@pytest.mark.unit
def test_verify_helper_matches_make_envelope() -> None:
    raw = make_envelope(SECRET, _Node("n1"), "heartbeat", {"k": 1}, msg_id="n1-5")
    import json

    envelope = json.loads(raw.decode())
    from src.infrastructure.mesh.gossip.serializer import canonical_json

    assert verify(SECRET, canonical_json(envelope["body"]), envelope["sig"]) is True
    assert verify(OTHER, canonical_json(envelope["body"]), envelope["sig"]) is False
