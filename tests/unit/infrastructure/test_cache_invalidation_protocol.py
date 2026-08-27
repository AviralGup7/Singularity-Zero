import unittest
from src.infrastructure.cache.cache_manager import CacheManager


class TestCacheInvalidationProtocol(unittest.TestCase):
    def test_cache_generation_bump_and_outbox_events(self) -> None:
        cm = CacheManager()
        self.assertEqual(cm.cache_generation, 1)

        # Store tagged item
        cm.set("finding_123", {"status": "OPEN"}, tags={"finding:F-123", "target:api.example.com"})
        self.assertTrue(cm.exists("finding_123"))

        # Invalidation event from Outbox: FINDING_FALSE_POSITIVE
        purged = cm.handle_outbox_invalidation_event(
            "FINDING_FALSE_POSITIVE",
            {"finding_id": "F-123", "target": "api.example.com"},
        )
        self.assertEqual(purged, 1)
        self.assertFalse(cm.exists("finding_123"))

        # Policy update outbox event bumps generation
        gen_before = cm.cache_generation
        cm.handle_outbox_invalidation_event("POLICY_UPDATED", {})
        self.assertEqual(cm.cache_generation, gen_before + 1)


if __name__ == "__main__":
    unittest.main()

