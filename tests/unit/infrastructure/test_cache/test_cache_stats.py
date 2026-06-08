import unittest

from src.infrastructure.cache.models import (
    CacheStats,
)


class TestCacheStats(unittest.TestCase):
    def test_defaults(self) -> None:
        s = CacheStats()
        assert s.total_entries == 0
        assert s.active_entries == 0

    def test_merge(self) -> None:
        s1 = CacheStats(total_entries=10, l1_entries=5)
        s2 = CacheStats(total_entries=20, l2_entries=15)
        merged = s1.merge(s2)
        assert merged.total_entries == 30
        assert merged.l1_entries == 5
        assert merged.l2_entries == 15
