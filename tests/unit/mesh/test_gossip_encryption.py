import json
import unittest
from dataclasses import dataclass

from src.infrastructure.mesh.gossip.serializer import (
    decrypt_mesh_payload,
    encrypt_mesh_payload,
    make_envelope,
    parse_envelope,
)


@dataclass
class DummyNode:
    id: str = "node_test_01"
    host: str = "127.0.0.1"
    port: int = 9008


class TestGossipEncryption(unittest.TestCase):
    def test_derive_key_and_aes_gcm_roundtrip(self):
        secret = b"super_secret_mesh_key_123"
        payload = {
            "node_id": "worker_us_east_1",
            "targets": ["https://target1.example.com", "https://target2.example.com"],
            "findings_count": 42,
            "metadata": {"region": "us-east-1", "hlc": "1700000000.0:1"},
        }

        enc = encrypt_mesh_payload(secret, payload)
        self.assertIsInstance(enc, str)
        self.assertNotIn("https://target1.example.com", enc)

        dec = decrypt_mesh_payload(secret, enc)
        self.assertEqual(dec, payload)

    def test_make_envelope_and_parse_envelope_encrypted(self):
        secret = b"mesh_auth_secret_xyz"
        node = DummyNode()
        payload = {"discovered_subdomain": "admin.corp.internal", "score": 99.5}

        # 1. Build encrypted wire envelope
        wire_bytes = make_envelope(
            secret=secret,
            local_node=node,
            message_type="HEARTBEAT",
            payload=payload,
            encrypt=True,
        )

        # Wire bytes should NOT contain plaintext payload
        wire_str = wire_bytes.decode("utf-8")
        self.assertNotIn("admin.corp.internal", wire_str)
        self.assertIn("enc_payload", wire_str)

        # 2. Parse & decrypt wire envelope
        body, is_valid = parse_envelope(wire_bytes, secret=secret)
        self.assertTrue(is_valid)
        self.assertIsNotNone(body)
        self.assertEqual(body["payload"], payload)
        self.assertEqual(body["type"], "HEARTBEAT")

    def test_tampered_envelope_rejected(self):
        secret = b"mesh_auth_secret_xyz"
        node = DummyNode()
        payload = {"data": "sensitive"}

        wire_bytes = make_envelope(
            secret=secret,
            local_node=node,
            message_type="PING",
            payload=payload,
        )

        # Tamper wire bytes
        envelope = json.loads(wire_bytes.decode("utf-8"))
        envelope["body"]["msg_id"] = "tampered_msg_id"
        tampered_bytes = json.dumps(envelope).encode("utf-8")

        body, is_valid = parse_envelope(tampered_bytes, secret=secret)
        self.assertFalse(is_valid)
        self.assertIsNone(body)
