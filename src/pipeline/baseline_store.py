import hashlib
import time
from typing import Any, Optional
from src.pipeline.unified_cache import UnifiedCache

class ScreenshotBaselineStore:
    """Baseline manager mapping targets, URLs, and viewports to prior screenshots and DOM states."""

    def __init__(self, cache: Optional[UnifiedCache] = None) -> None:
        self.cache = cache if cache is not None else UnifiedCache()

    def _get_baseline_key(self, target: str, url: str, viewport: str) -> str:
        target_hash = hashlib.sha256(target.encode("utf-8")).hexdigest()
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
        clean_viewport = "".join(c if c.isalnum() else "_" for c in viewport)
        return f"screenshot:baseline:{target_hash}:{url_hash}:{clean_viewport}"

    def _get_blob_key(self, image_hash: str) -> str:
        return f"screenshot:blob:{image_hash}"

    def get_baseline(self, target: str, url: str, viewport: str) -> Optional[dict[str, Any]]:
        key = self._get_baseline_key(target, url, viewport)
        val = self.cache.get(key)
        if isinstance(val, dict):
            return val
        return None

    def get_screenshot_blob(self, image_hash: str) -> Optional[str]:
        """Returns the base64-encoded image bytes for the given image hash."""
        key = self._get_blob_key(image_hash)
        val = self.cache.get(key)
        if isinstance(val, str):
            return val
        return None

    def store_screenshot_blob(self, image_hash: str, image_base64: str) -> None:
        key = self._get_blob_key(image_hash)
        self.cache.set(key, image_base64)

    def update_baseline(
        self,
        target: str,
        url: str,
        viewport: str,
        image_hash: str,
        dom_hash: str,
        image_base64: str
    ) -> None:
        self.store_screenshot_blob(image_hash, image_base64)
        key = self._get_baseline_key(target, url, viewport)
        baseline_record = {
            "latest_image_hash": image_hash,
            "dom_hash": dom_hash,
            "timestamp": time.time()
        }
        self.cache.set(key, baseline_record)

    def should_skip_capture(self, target: str, url: str, viewport: str, current_dom_hash: str) -> bool:
        baseline = self.get_baseline(target, url, viewport)
        if not baseline:
            return False
        stored_dom_hash = baseline.get("dom_hash")
        return bool(stored_dom_hash and stored_dom_hash == current_dom_hash)
