import tempfile
import time
import unittest

from src.infrastructure.cache.backends import SQLiteBackend


class CacheTestBase(unittest.TestCase):
    def setUp(self) -> None:
        from pathlib import Path

        self.tmp_path = Path(tempfile.mkdtemp())

class TestSQLiteBackend(CacheTestBase):
    def test_set_and_get(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", {"data": "value"})
        assert backend.get("k1") == {"data": "value"}
        backend.close()

    def test_get_missing(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        assert backend.get("missing") is None
        backend.close()

    def test_delete(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1")
        assert backend.delete("k1") is True
        assert backend.get("k1") is None
        backend.close()

    def test_exists(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1")
        assert backend.exists("k1") is True
        assert backend.exists("missing") is False
        backend.close()

    def test_clear(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        count = backend.clear()
        assert count == 2
        backend.close()

    def test_size(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        assert backend.size() == 2
        backend.close()

    def test_ttl_expiry(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1", ttl=0)
        time.sleep(0.1)
        assert backend.get("k1") is None
        backend.close()

    def test_cleanup_expired(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1", ttl=0)
        backend.set("k2", "v2", ttl=3600)
        time.sleep(0.1)
        removed = backend.cleanup_expired()
        assert removed == 1
        backend.close()

    def test_get_stats(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        stats = backend.get_stats()
        assert stats["backend"] == "sqlite"
        backend.close()

    def test_get_by_namespace(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set_with_metadata("ns1:k1", "v1", namespace="ns1")
        results = backend.get_by_namespace("ns1")
        assert len(results) == 1
        backend.close()

    def test_get_by_tag(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set_with_metadata("k1", "v1", tags={"tag1", "tag2"})
        keys = backend.get_by_tag("tag1")
        assert "k1" in keys
        backend.close()

    def test_get_by_tag_skips_expired_entries(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set_with_metadata("k1", "v1", ttl=0, tags={"tag1"})
        time.sleep(0.1)
        assert backend.get_by_tag("tag1") == []
        backend.close()

    def test_get_dependents_matches_dependency_tokens(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set_with_metadata("child", "v1", depends_on={"ns:root"})
        backend.set_with_metadata("false-positive", "v2", depends_on={"ns:root2"})
        assert backend.get_dependents("root") == ["child"]
        assert backend.get_dependents("ns:root") == ["child"]
        backend.close()

    def test_evict_lru(self) -> None:
        backend = SQLiteBackend(db_path=str(self.tmp_path / "test.db"))
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        backend.get("k1")
        removed = backend.evict_lru(1)
        assert removed == 1
        backend.close()
