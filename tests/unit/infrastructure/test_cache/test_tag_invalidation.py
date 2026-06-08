import unittest

from src.infrastructure.cache.invalidation import (
    TagInvalidation,
)
from src.infrastructure.cache.models import (
    CacheEntry,
)


class TestTagInvalidation(unittest.TestCase):
    def test_invalidate_by_tag(self) -> None:
        strategy = TagInvalidation()
        store = {
            "k1": CacheEntry(key="k1", value="v1", tags={"a", "b"}),
            "k2": CacheEntry(key="k2", value="v2", tags={"b"}),
            "k3": CacheEntry(key="k3", value="v3", tags={"c"}),
        }
        strategy.register_entry("k1", {"a", "b"})
        strategy.register_entry("k2", {"b"})
        strategy.register_entry("k3", {"c"})
        removed = strategy.invalidate(store, tags={"a"})
        assert "k1" in removed
        assert "k2" not in removed

    def test_no_tags(self) -> None:
        strategy = TagInvalidation()
        store = {"k1": CacheEntry(key="k1", value="v1")}
        assert strategy.invalidate(store, tags=None) == []

    def test_get_keys_by_tag(self) -> None:
        strategy = TagInvalidation()
        strategy.register_entry("k1", {"tag1"})
        strategy.register_entry("k2", {"tag1"})
        strategy.register_entry("k3", {"tag2"})
        keys = strategy.get_keys_by_tag("tag1")
        assert "k1" in keys
        assert "k2" in keys
        assert "k3" not in keys

    def test_name(self) -> None:
        assert TagInvalidation().name() == "Tag"
