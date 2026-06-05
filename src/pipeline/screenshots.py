"""Screenshot capture module for visual documentation of live hosts.

Uses headless Chromium-based browsers to capture screenshots of target
hosts for inclusion in pipeline reports.
"""

import base64
import hashlib
import shutil
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image
import requests
from scipy.fft import dct
import urllib3

from src.core.logging.pipeline_logging import emit_warning
from src.core.models import Config
from src.pipeline.baseline_store import ScreenshotBaselineStore
from src.pipeline.storage import ensure_dir
from src.pipeline.tools import RetryPolicy, build_retry_policy, run_command

# Disable insecure request warnings for target probing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def detect_browser(candidates: list[str]) -> str | None:
    for candidate in [*candidates, "msedge", "chrome", "chromium", "chromium-browser"]:
        if not candidate:
            continue
        path = Path(candidate)
        if path.exists():
            return str(path)
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def safe_name_from_url(url: str) -> str:
    clean = "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in url)
    clean = clean.strip("._") or "root"
    return clean[:180]


def compute_dom_hash(url: str) -> str:
    """Fetch the DOM / HTML content of a URL and compute its hash."""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows / Security Pipeline Screenshot)"}
        response = requests.get(url, timeout=5, headers=headers, verify=False)
        return hashlib.sha256(response.text.encode("utf-8")).hexdigest()
    except Exception:
        return ""


def is_blank_page(image_path: Path, threshold_pct: float = 0.5) -> bool:
    """Returns True if the non-white pixel count is below the given threshold percentage."""
    try:
        with Image.open(image_path) as img:
            img_rgb = img.convert("RGB")
            arr = np.array(img_rgb)
            # White is 255, 255, 255
            non_white_mask = (arr[:, :, 0] < 255) | (arr[:, :, 1] < 255) | (arr[:, :, 2] < 255)
            non_white_count = np.sum(non_white_mask)
            total_pixels = arr.shape[0] * arr.shape[1]
            non_white_pct = (non_white_count / total_pixels) * 100
            return non_white_pct <= threshold_pct
    except Exception:
        return False


def compute_phash(image_path: Path) -> str:
    """Compute an 8x8 DCT-based perceptual hash of an image."""
    try:
        with Image.open(image_path) as img:
            img = img.convert("L").resize((32, 32), Image.Resampling.BILINEAR)
            pixels = np.array(img, dtype=float)
            # 2D Discrete Cosine Transform
            dct_val = dct(dct(pixels, axis=0, norm='ortho'), axis=1, norm='ortho')
            dct_low = dct_val[:8, :8]
            dct_low_flat = dct_low.flatten()
            median_val = np.median(dct_low_flat[1:])
            bits = (dct_low_flat > median_val).astype(int)
            return "".join(f"{val:02x}" for val in np.packbits(bits))
    except Exception:
        return ""


def hamming_distance(hash1: str, hash2: str) -> int:
    try:
        b1 = bytes.fromhex(hash1)
        b2 = bytes.fromhex(hash2)
        return sum(bin(x1 ^ x2).count('1') for x1, x2 in zip(b1, b2))
    except Exception:
        return 999


def _capture_single(
    url: str,
    browser: str,
    screenshot_dir: Path,
    run_dir: Path,
    settings: dict[str, Any],
    retry_policy: RetryPolicy,
    baseline_store: ScreenshotBaselineStore,
    target_name: str,
) -> dict[str, Any]:
    """Capture a screenshot for a single URL, using baseline management and fidelity checks."""
    destination = screenshot_dir / f"{safe_name_from_url(url)}.png"
    viewport = settings.get("window_size", "1440,900")
    
    # 1. Fetch DOM and check if we can skip capture
    dom_hash = compute_dom_hash(url)
    if dom_hash and baseline_store.should_skip_capture(target_name, url, viewport, dom_hash):
        baseline = baseline_store.get_baseline(target_name, url, viewport)
        if baseline:
            image_hash = baseline["latest_image_hash"]
            image_base64 = baseline_store.get_screenshot_blob(image_hash)
            if image_base64:
                try:
                    destination.write_bytes(base64.b64decode(image_base64))
                    return {
                        "url": url,
                        "status": "ok",
                        "file": str(destination.relative_to(run_dir)),
                        "error": "",
                        "skipped_capture": True,
                        "image_hash": image_hash,
                    }
                except Exception as exc:  # noqa: BLE001
                    emit_warning(f"failed to restore cached baseline screenshot: {exc}")

    # 2. Capture screenshot via browser
    command = [
        browser,
        "--headless",
        "--disable-gpu",
        "--hide-scrollbars",
        f"--window-size={viewport}",
        f"--screenshot={destination}",
        url,
    ]
    try:
        run_command(
            command,
            timeout=int(settings.get("per_url_timeout_seconds", 20)),
            retry_policy=retry_policy,
        )
        status = "ok" if destination.exists() else "missing"
        error = ""
    except Exception as exc:  # noqa: BLE001
        status = "error"
        error = str(exc)
        emit_warning(f"screenshot failed for {url}: {exc}")

    # 3. Apply fidelity checks and perceptual hashing
    image_hash = ""
    if status == "ok" and destination.exists():
        # Blank/WAF page detection (Content-Presence Gate)
        if is_blank_page(destination, threshold_pct=0.5):
            status = "blank"
            error = "Blank page detected (possible WAF block)"
            emit_warning(f"screenshot blank for {url}: WAF or bot block suspected.")
            try:
                destination.unlink()
            except OSError:
                pass
        else:
            image_hash = compute_phash(destination)
            if image_hash:
                # Deduplication check: compare against baseline
                baseline = baseline_store.get_baseline(target_name, url, viewport)
                if baseline:
                    base_hash = baseline.get("latest_image_hash")
                    if base_hash and hamming_distance(image_hash, base_hash) <= 4:
                        # Re-use baseline image content if perceptually similar to reduce storage overhead
                        base_blob = baseline_store.get_screenshot_blob(base_hash)
                        if base_blob:
                            try:
                                destination.write_bytes(base64.b64decode(base_blob))
                                image_hash = base_hash
                            except Exception:
                                pass
                
                # Update the store
                try:
                    with open(destination, "rb") as f:
                        img_b64 = base64.b64encode(f.read()).decode("ascii")
                    baseline_store.update_baseline(
                        target_name,
                        url,
                        viewport,
                        image_hash,
                        dom_hash,
                        img_b64
                    )
                except Exception as exc:
                    emit_warning(f"failed to update baseline store: {exc}")

    return {
        "url": url,
        "status": status,
        "file": str(destination.relative_to(run_dir)) if (destination.exists() and status == "ok") else "",
        "error": error,
        "image_hash": image_hash,
    }


def capture_screenshots(
    live_hosts: set[str], run_dir: Path, config: Config
) -> list[dict[str, Any]]:
    settings = config.screenshots
    if not settings.get("enabled"):
        return []

    browser = detect_browser(settings.get("browser_paths", []))
    if not browser:
        emit_warning("screenshot capture enabled but no browser binary was found.")
        return []

    screenshot_dir = run_dir / "screenshots"
    ensure_dir(screenshot_dir)

    retry_policy = build_retry_policy(config.tools, settings)
    max_workers = int(settings.get("max_workers", 4))
    targets = sorted(live_hosts)[: int(settings.get("max_hosts", 25))]

    baseline_store = ScreenshotBaselineStore()
    target_name = getattr(config, "target_name", "default_target")

    captures: list[dict[str, Any]] = []
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(
                _capture_single,
                url,
                browser,
                screenshot_dir,
                run_dir,
                settings,
                retry_policy,
                baseline_store,
                target_name,
            ): url
            for url in targets
        }
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                captures.append(future.result())
            except Exception as exc:  # noqa: BLE001
                emit_warning(f"screenshot failed for {url}: {exc}")
                captures.append(
                    {
                        "url": url,
                        "status": "error",
                        "file": "",
                        "error": str(exc),
                    }
                )

    # Sort by URL for consistent output
    captures.sort(key=lambda c: c["url"])
    return captures

