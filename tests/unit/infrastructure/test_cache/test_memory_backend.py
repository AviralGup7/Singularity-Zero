import time
import unittest

from src.infrastructure.cache.backends import MemoryBackend


class TestMemoryBackend(unittest.TestCase):
    def test_set_and_get(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        assert backend.get("k1") == "v1"

    def test_get_missing(self) -> None:
        backend = MemoryBackend()
        assert backend.get("missing") is None

    def test_delete(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        assert backend.delete("k1") is True
        assert backend.get("k1") is None

    def test_delete_missing(self) -> None:
        backend = MemoryBackend()
        assert backend.delete("missing") is False

    def test_exists(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        assert backend.exists("k1") is True
        assert backend.exists("missing") is False

    def test_clear(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        count = backend.clear()
        assert count == 2
        assert backend.size() == 0

    def test_size(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        assert backend.size() == 2

    def test_ttl_expiry(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1", ttl=0)
        time.sleep(0.1)
        assert backend.get("k1") is None

    def test_cleanup_expired(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1", ttl=0)
        backend.set("k2", "v2", ttl=3600)
        time.sleep(0.1)
        removed = backend.cleanup_expired()
        assert removed == 1
        assert backend.get("k2") == "v2"

    def test_evict_lru(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        backend.set("k3", "v3")
        backend.get("k1")
        backend.get("k2")
        removed = backend.evict_lru(1)
        assert removed == 1

    def test_max_entries_is_enforced_on_set(self) -> None:
        backend = MemoryBackend(max_entries=2)
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        backend.set("k3", "v3")
        assert backend.size() == 2

    def test_get_all(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        backend.set("k2", "v2")
        all_entries = backend.get_all()
        assert all_entries["k1"] == "v1"
        assert all_entries["k2"] == "v2"

    def test_get_stats(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        stats = backend.get_stats()
        assert stats["backend"] == "memory"
        assert stats["total_entries"] == 1

    def test_close(self) -> None:
        backend = MemoryBackend()
        backend.set("k1", "v1")
        backend.close()
        assert backend.size() == 0
