import unittest

from src.infrastructure.cache.invalidation import (
    LRUInvalidation,
)
from src.infrastructure.cache.models import (
    CacheEntry,
)


class TestLRUInvalidation(unittest.TestCase):
    def test_evict_when_over(self) -> None:
        strategy = LRUInvalidation(max_entries=2, eviction_count=1)
        store = {
            "k1": CacheEntry(key="k1", value="v1"),
            "k2": CacheEntry(key="k2", value="v2"),
            "k3": CacheEntry(key="k3", value="v3"),
        }
        removed = strategy.invalidate(store)
        assert len(removed) >= 1

    def test_no_evict_when_under(self) -> None:
        strategy = LRUInvalidation(max_entries=10)
        store = {"k1": CacheEntry(key="k1", value="v1")}
        removed = strategy.invalidate(store)
        assert removed == []

    def test_name(self) -> None:
        assert LRUInvalidation().name() == "LRU"
