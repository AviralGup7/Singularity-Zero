"""
Message serialization utilities for the gossip protocol.

Handles canonical JSON encoding, HMAC signing/verification, and
envelope construction/parsing over the wire.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


def derive_mesh_key(secret: bytes) -> bytes:
    """Derive a 256-bit symmetric AES-GCM key from the mesh secret."""
    return hashlib.sha256(b"mesh_gossip_aes_gcm:" + secret).digest()


def encrypt_mesh_payload(secret: bytes, payload: dict[str, Any]) -> str:
    """Encrypt payload dictionary using AES-256-GCM, returning base64-encoded ciphertext."""
    key = derive_mesh_key(secret)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit standard GCM nonce
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_mesh_payload(secret: bytes, enc_payload_b64: str) -> dict[str, Any]:
    """Decrypt base64-encoded AES-256-GCM ciphertext back into payload dictionary."""
    key = derive_mesh_key(secret)
    aesgcm = AESGCM(key)
    raw = base64.b64decode(enc_payload_b64.encode("ascii"))
    nonce = raw[:12]
    ciphertext = raw[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    decoded = json.loads(plaintext.decode("utf-8"))
    return decoded if isinstance(decoded, dict) else {}


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
    encrypt: bool = True,
) -> bytes:
    """Build an authenticated, encrypted wire envelope."""
    from dataclasses import asdict

    node_dict = asdict(local_node)

    enc_payload = None
    if encrypt and secret:
        try:
            enc_payload = encrypt_mesh_payload(secret, payload)
        except Exception as exc:
            logger.debug("gossip/serializer: payload encryption fallback (%s)", exc)

    body = {
        "type": message_type,
        "msg_id": msg_id or f"{node_dict['id']}-{uuid.uuid4().hex}",
        "source": node_dict,
        "payload": payload if enc_payload is None else {},
        "enc_payload": enc_payload,
        "sent_at": time.time(),
    }
    body_json = canonical_json(body)
    envelope = {"body": body, "sig": sign(secret, body_json)}
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def parse_envelope(data: bytes, secret: bytes | None = None) -> tuple[Any, bool]:
    """Decode, decrypt, and HMAC-verify a wire envelope, returning (body, is_valid).

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

        # Decrypt payload if encrypted
        enc_payload = body.get("enc_payload")
        if enc_payload:
            try:
                decrypted = decrypt_mesh_payload(secret, enc_payload)
                body["payload"] = decrypted
            except Exception as exc:
                logger.warning("gossip/serializer: AES-GCM decryption failed: %s", exc)
                return None, False

        return body, True
    except Exception:
        logger.debug("gossip/serializer: dropped malformed envelope", exc_info=True)
        return None, False
