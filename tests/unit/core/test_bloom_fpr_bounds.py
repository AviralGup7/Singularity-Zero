import unittest

from src.core.frontier.bloom import GenerationalBloomFilter


class TestBoundedFPRBloomFilter(unittest.TestCase):
    def test_bounded_fpr_and_rotation_under_saturation(self) -> None:
        # Small capacity to test auto-rotation upon capacity/FPR saturation
        bf = GenerationalBloomFilter(
            capacity=100,
            error_rate=0.001,
            fill_ratio_threshold=0.70,
            max_fpr_threshold=0.005,
        )

        self.assertEqual(bf.generation, 1)
        stats = bf.get_stats()
        self.assertEqual(stats["target_fpr"], 0.001)
        self.assertEqual(stats["max_fpr_threshold"], 0.005)

        # Add 120 elements (exceeds capacity=100)
        for i in range(120):
            bf.add(f"https://example.com/item_{i}")

        # Must auto-rotate to next generation
        self.assertGreaterEqual(bf.generation, 2)

        # Elements added in generation 1 must still be visible in generation 2 (via previous generation)
        self.assertTrue(bf.contains("https://example.com/item_0"))
        self.assertTrue(bf.contains("https://example.com/item_119"))


if __name__ == "__main__":
    unittest.main()
