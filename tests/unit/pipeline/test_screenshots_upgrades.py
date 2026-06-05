import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw

from src.pipeline.baseline_store import ScreenshotBaselineStore
from src.pipeline.screenshot_diff import _compute_ssim, compute_screenshot_diff
from src.pipeline.screenshots import (
    compute_dom_hash,
    compute_phash,
    hamming_distance,
    is_blank_page,
)
from src.pipeline.unified_cache import UnifiedCache


class TestScreenshotsUpgrades(unittest.TestCase):
    def setUp(self) -> None:
        # Create a temporary directory for saving test images
        self.test_dir = tempfile.TemporaryDirectory()
        self.test_path = Path(self.test_dir.name)

        # Create sample images
        self.white_img_path = self.test_path / "white.png"
        self.blank_img = Image.new("RGB", (200, 200), (255, 255, 255))
        self.blank_img.save(self.white_img_path)

        self.content_img_path = self.test_path / "content.png"
        self.content_img = Image.new("RGB", (200, 200), (255, 255, 255))
        draw = ImageDraw.Draw(self.content_img)
        draw.rectangle([50, 50, 150, 150], fill=(0, 0, 0))  # A black block
        self.content_img.save(self.content_img_path)

        # Slightly modified content image for SSIM and diff testing
        self.modified_img_path = self.test_path / "modified.png"
        self.modified_img = Image.new("RGB", (200, 200), (255, 255, 255))
        draw_mod = ImageDraw.Draw(self.modified_img)
        draw_mod.rectangle([50, 50, 150, 150], fill=(0, 0, 0))
        draw_mod.point((10, 10), fill=(250, 250, 250))  # Minor noise (off-white pixel)
        self.modified_img.save(self.modified_img_path)

        # Initialize test cache & store
        self.cache = UnifiedCache(file_root=self.test_path / "cache")
        self.store = ScreenshotBaselineStore(cache=self.cache)

    def tearDown(self) -> None:
        self.cache.close()
        self.test_dir.cleanup()

    def test_blank_page_gate(self) -> None:
        # All-white image should be detected as blank
        self.assertTrue(is_blank_page(self.white_img_path, threshold_pct=0.5))
        # Image with large black block should NOT be blank
        self.assertFalse(is_blank_page(self.content_img_path, threshold_pct=0.5))

    def test_perceptual_hashing(self) -> None:
        hash_white = compute_phash(self.white_img_path)
        hash_content = compute_phash(self.content_img_path)
        hash_modified = compute_phash(self.modified_img_path)

        self.assertIsNotNone(hash_white)
        self.assertIsNotNone(hash_content)

        # Identical files should yield 0 Hamming distance
        self.assertEqual(hamming_distance(hash_content, hash_content), 0)

        # Minor modifications should yield low Hamming distance (<= 4)
        dist_mod = hamming_distance(hash_content, hash_modified)
        self.assertTrue(dist_mod <= 4, f"Hamming distance was {dist_mod}")

        # Completely different images should have high Hamming distance
        dist_diff = hamming_distance(hash_white, hash_content)
        self.assertTrue(dist_diff > 4, f"Hamming distance was {dist_diff}")

    def test_baseline_store_cache_operations(self) -> None:
        target = "target_org"
        url = "http://example.org"
        viewport = "1440,900"
        image_hash = "aabbccddeeff0011"
        dom_hash = "1234567890abcdef"
        image_data = b"fake_png_data"
        image_base64 = base64.b64encode(image_data).decode("ascii")

        # Initially, baseline shouldn't exist
        self.assertIsNone(self.store.get_baseline(target, url, viewport))

        # Store baseline
        self.store.update_baseline(target, url, viewport, image_hash, dom_hash, image_base64)

        # Retrieve and verify baseline
        baseline = self.store.get_baseline(target, url, viewport)
        self.assertIsNotNone(baseline)
        self.assertEqual(baseline["latest_image_hash"], image_hash)
        self.assertEqual(baseline["dom_hash"], dom_hash)

        # Retrieve and verify blob bytes
        blob_b64 = self.store.get_screenshot_blob(image_hash)
        self.assertEqual(blob_b64, image_base64)

        # Check skip capture conditions
        self.assertTrue(self.store.should_skip_capture(target, url, viewport, dom_hash))
        self.assertFalse(self.store.should_skip_capture(target, url, viewport, "different_dom_hash"))

    def test_windowed_ssim_accuracy(self) -> None:
        # SSIM between identical images must be exactly 1.0
        ssim_self = _compute_ssim(self.content_img, self.content_img)
        self.assertAlmostEqual(ssim_self, 1.0, places=4)

        # SSIM between slightly modified images should be high but less than 1.0
        ssim_mod = _compute_ssim(self.content_img, self.modified_img)
        self.assertTrue(0.8 < ssim_mod < 1.0, f"SSIM was {ssim_mod}")

        # SSIM between completely different images should be low
        ssim_diff = _compute_ssim(self.blank_img, self.content_img)
        self.assertTrue(ssim_diff < 0.8, f"SSIM was {ssim_diff}")

    def test_compute_screenshot_diff_with_tiled_highlights(self) -> None:
        diff_out_path = self.test_path / "diff.png"
        result = compute_screenshot_diff(
            self.content_img_path,
            self.modified_img_path,
            save_path=diff_out_path
        )

        self.assertIsNotNone(result.diff_image_base64)
        self.assertTrue(diff_out_path.exists())

        # Load diff image and ensure it has 3 panels width
        with Image.open(diff_out_path) as diff_img:
            self.assertEqual(diff_img.width, 200 * 3)
            self.assertEqual(diff_img.height, 200 + 40)
