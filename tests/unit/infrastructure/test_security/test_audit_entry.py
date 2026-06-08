import unittest

from src.infrastructure.security.audit import AuditEntry


class TestAuditEntry(unittest.TestCase):
    def test_compute_hash(self) -> None:
        entry = AuditEntry(
            id=1, timestamp="2024-01-01T00:00:00", event="auth.success", severity="info"
        )
        h1 = entry.compute_hash()
        h2 = entry.compute_hash()
        assert h1 == h2

    def test_compute_hash_with_secret(self) -> None:
        entry = AuditEntry(
            id=1, timestamp="2024-01-01T00:00:00", event="auth.success", severity="info"
        )
        h1 = entry.compute_hash(hmac_secret="secret")
        h2 = entry.compute_hash(hmac_secret="different")
        assert h1 != h2

    def test_finalize(self) -> None:
        entry = AuditEntry(
            id=1, timestamp="2024-01-01T00:00:00", event="auth.success", severity="info"
        )
        entry.finalize()
        assert entry.entry_hash != ""
