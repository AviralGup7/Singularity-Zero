"""B19: receipt HMAC material is HKDF-domain-separated."""

from __future__ import annotations

import unittest

from src.core.frontier.receipt_crypto import domain_separated_key


class TestHkdfDomainSeparation(unittest.TestCase):
    def test_purposes_diverge(self) -> None:
        master = b"unit-test-master-secret"
        receipt = domain_separated_key(master, purpose="receipt-hmac")
        jwt = domain_separated_key(master, purpose="jwt-hs256")
        mesh = domain_separated_key(master, purpose="mesh-aead")
        self.assertEqual(len(receipt), 32)
        self.assertNotEqual(receipt, jwt)
        self.assertNotEqual(receipt, mesh)
        self.assertNotEqual(jwt, mesh)
        self.assertEqual(receipt, domain_separated_key(master, purpose="receipt-hmac"))


if __name__ == "__main__":
    unittest.main()
