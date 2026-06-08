import time
import unittest

from src.infrastructure.cache.models import (
    CacheEntry,
)


class TestCacheEntry(unittest.TestCase):
    def test_entry_defaults(self) -> None:
        entry = CacheEntry(key="k1", value="v1")
        assert entry.key == "k1"
        assert entry.value == "v1"
        assert entry.access_count == 0
        assert entry.tags == set()
        assert entry.depends_on == set()

    def test_entry_is_expired_false(self) -> None:
        entry = CacheEntry(key="k1", value="v1", expires_at=time.time() + 3600)
        assert entry.is_expired is False

    def test_entry_is_expired_true(self) -> None:
        entry = CacheEntry(key="k1", value="v1", expires_at=time.time() - 10)
        assert entry.is_expired is True

    def test_entry_no_expiry(self) -> None:
        entry = CacheEntry(key="k1", value="v1", expires_at=None)
        assert entry.is_expired is False

    def test_entry_age_seconds(self) -> None:
        entry = CacheEntry(key="k1", value="v1")
        time.sleep(0.1)
        assert entry.age_seconds > 0

    def test_entry_ttl_remaining(self) -> None:
        entry = CacheEntry(key="k1", value="v1", expires_at=time.time() + 100)
        remaining = entry.ttl_remaining
        assert 95 < remaining <= 100

    def test_entry_ttl_remaining_none(self) -> None:
        entry = CacheEntry(key="k1", value="v1", expires_at=None)
        assert entry.ttl_remaining is None

    def test_entry_touch(self) -> None:
        entry = CacheEntry(key="k1", value="v1")
        old_access = entry.last_accessed
        time.sleep(0.1)
        entry.touch()
        assert entry.last_accessed > old_access
        assert entry.access_count == 1

    def test_entry_compute_size(self) -> None:
        entry = CacheEntry(key="k1", value={"data": "test"})
        size = entry.compute_size()
        assert size > 0
