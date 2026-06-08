import unittest

from src.infrastructure.cache.invalidation import (
    VersionInvalidation,
)
from src.infrastructure.cache.models import (
    CacheEntry,
)


class TestVersionInvalidation(unittest.TestCase):
    def test_bump_version(self) -> None:
        strategy = VersionInvalidation(initial_version="1")
        new_ver = strategy.bump_version()
        assert new_ver == "2"

    def test_invalidate_old_versions(self) -> None:
        strategy = VersionInvalidation(initial_version="1")
        store = {
            "k1": CacheEntry(key="k1", value="v1"),
            "k2": CacheEntry(key="k2", value="v2"),
        }
        strategy.register_entry("k1", version="1")
        strategy.bump_version()
        removed = strategy.invalidate(store, all_old=True)
        assert "k1" in removed

    def test_name(self) -> None:
        assert VersionInvalidation().name() == "Version"
