import hashlib
import time
from typing import Any

from src.pipeline.unified_cache import UnifiedCache

_TTL_SECONDS = 24 * 3600


class ScreenshotBaselineStore:
    """Baseline manager mapping targets, URLs, and viewports to prior screenshots and DOM states."""

    def __init__(self, cache: UnifiedCache | None = None) -> None:
        self.cache = cache if cache is not None else UnifiedCache()

    def _get_baseline_key(self, target: str, url: str, viewport: str) -> str:
        target_hash = hashlib.sha256(target.encode("utf-8")).hexdigest()
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
        clean_viewport = "".join(c if c.isalnum() else "_" for c in viewport)
        return f"screenshot:baseline:{target_hash}:{url_hash}:{clean_viewport}"

    def _get_blob_key(self, image_hash: str) -> str:
        return f"screenshot:blob:{image_hash}"

    def get_baseline(self, target: str, url: str, viewport: str) -> dict[str, Any] | None:
        key = self._get_baseline_key(target, url, viewport)
        val = self.cache.get(key)
        if isinstance(val, dict):
            return val
        return None

    def get_screenshot_blob(self, image_hash: str) -> str | None:
        key = self._get_blob_key(image_hash)
        val = self.cache.get(key)
        if isinstance(val, str):
            return val
        return None

    def store_screenshot_blob(self, image_hash: str, image_base64: str) -> None:
        key = self._get_blob_key(image_hash)
        self.cache.set(key, image_base64)

    def _store_transactional(
        self, record_key: str, record: dict[str, Any], blob_key: str, blob_data: str
    ) -> None:
        self.cache.set(blob_key, blob_data)
        if self.cache.get(blob_key) is None:
            raise RuntimeError("Baseline blob write verification failed")
        record["baseline_version"] = int(record.get("baseline_version", 0)) + 1
        record["stale_on"] = time.time() + _TTL_SECONDS
        self.cache.set(record_key, record)

    def update_baseline(
        self,
        target: str,
        url: str,
        viewport: str,
        image_hash: str,
        dom_hash: str,
        image_base64: str,
    ) -> None:
        blob_key = self._get_blob_key(image_hash)
        key = self._get_baseline_key(target, url, viewport)
        existing = self.cache.get(key)
        baseline_version = 0
        if isinstance(existing, dict):
            baseline_version = int(existing.get("baseline_version", 0))
        record = {
            "latest_image_hash": image_hash,
            "dom_hash": dom_hash,
            "timestamp": time.time(),
            "baseline_version": baseline_version,
            "stale_on": time.time() + _TTL_SECONDS,
        }
        self._store_transactional(key, record, blob_key, image_base64)

    def should_skip_capture(
        self, target: str, url: str, viewport: str, current_dom_hash: str
    ) -> bool:
        baseline = self.get_baseline(target, url, viewport)
        if not baseline:
            return False
        stale_on = baseline.get("stale_on")
        if stale_on is not None and time.time() > float(stale_on):
            return False
        stored_dom_hash = baseline.get("dom_hash")
        return bool(stored_dom_hash and stored_dom_hash == current_dom_hash)
