import tempfile
import time
import unittest

from src.infrastructure.cache.backends import FileBackend


class CacheTestBase(unittest.TestCase):
    def setUp(self) -> None:
        from pathlib import Path

        self.tmp_path = Path(tempfile.mkdtemp())


class TestFileBackend(CacheTestBase):
    def test_set_and_get(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", {"data": "value"})
        assert backend.get("k1") == {"data": "value"}
        backend.close()

    def test_get_missing(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        assert backend.get("missing") is None
        backend.close()

    def test_delete(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", "v1")
        assert backend.delete("k1") is True
        assert backend.get("k1") is None
        backend.close()

    def test_exists(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", "v1")
        assert backend.exists("k1") is True
        assert backend.exists("missing") is False
        backend.close()

    def test_clear(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        count = backend.clear()
        assert count == 2
        backend.close()

    def test_size(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", "v1")
        assert backend.size() == 1
        backend.close()

    def test_ttl_expiry(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", "v1", ttl=0)
        time.sleep(0.1)
        assert backend.get("k1") is None
        backend.close()

    def test_cleanup_expired(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("k1", "v1", ttl=0)
        backend.set("k2", "v2", ttl=3600)
        time.sleep(0.1)
        removed = backend.cleanup_expired()
        assert removed == 1
        backend.close()

    def test_get_stats(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        stats = backend.get_stats()
        assert stats["backend"] == "file"
        backend.close()

    def test_get_keys_by_namespace(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("ns1:k1", "v1")
        backend.set("ns2:k2", "v2")
        keys = backend.get_keys_by_namespace("ns1")
        assert "ns1:k1" in keys
        backend.close()

    def test_key_filenames_do_not_collide_when_index_is_missing(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("a:b", "colon")
        backend.set("a_b", "underscore")
        (self.tmp_path / ".cache_index.json").unlink()
        backend = FileBackend(cache_dir=str(self.tmp_path))
        assert backend.get("a:b") == "colon"
        assert backend.get("a_b") == "underscore"
        backend.close()

    def test_delete_returns_true_for_orphaned_file(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("orphan", "value")
        (self.tmp_path / ".cache_index.json").unlink()
        backend = FileBackend(cache_dir=str(self.tmp_path))
        assert backend.delete("orphan") is True
        assert backend.exists("orphan") is False
        backend.close()

    def test_exists_handles_orphaned_none_value(self) -> None:
        backend = FileBackend(cache_dir=str(self.tmp_path))
        backend.set("none-value", None)
        (self.tmp_path / ".cache_index.json").unlink()
        backend = FileBackend(cache_dir=str(self.tmp_path))
        assert backend.exists("none-value") is True
        backend.close()
