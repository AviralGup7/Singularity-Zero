"""
Message serialization utilities for the gossip protocol.

Handles canonical JSON encoding, HMAC signing/verification, and
envelope construction/parsing over the wire.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Any

logger = logging.getLogger(__name__)


def canonical_json(data: dict[str, Any]) -> bytes:
    """Stable, deterministic JSON encoding for signature inputs."""
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign(secret: bytes, data: bytes) -> str:
    """Create HMAC-SHA256 signature."""
    return hmac.new(secret, data, hashlib.sha256).hexdigest()


def verify(secret: bytes, data: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 signature."""
    expected = sign(secret, data)
    return hmac.compare_digest(expected, signature)


def make_envelope(
    secret: bytes,
    local_node: Any,
    message_type: str,
    payload: dict[str, Any],
    msg_id: str | None = None,
) -> bytes:
    """Build an authenticated wire envelope."""
    from dataclasses import asdict

    node_dict = asdict(local_node)
    body = {
        "type": message_type,
        "msg_id": msg_id or f"{node_dict['id']}-{uuid.uuid4().hex}",
        "source": node_dict,
        "payload": payload,
        "sent_at": time.time(),
    }
    body_json = canonical_json(body)
    envelope = {"body": body, "sig": sign(secret, body_json)}
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def parse_envelope(data: bytes, secret: bytes | None = None) -> tuple[Any, bool]:
    """Decode and HMAC-verify a wire envelope, returning (body, is_valid).

    A well-formed JSON envelope is not enough: ``is_valid`` is True only
    when ``secret`` is provided and the HMAC over the canonical body
    matches. Unsigned or tampered envelopes return ``(None, False)``.
    """
    try:
        envelope = json.loads(data.decode("utf-8"))
        body = envelope["body"]
        signature = envelope.get("sig", "")
        if not isinstance(body, dict) or not isinstance(signature, str) or secret is None:
            return None, False
        if not verify(secret, canonical_json(body), signature):
            logger.debug("gossip/serializer: HMAC verification failed")
            return None, False
        return body, True
    except Exception:
        logger.debug("gossip/serializer: dropped malformed envelope", exc_info=True)
        return None, False
