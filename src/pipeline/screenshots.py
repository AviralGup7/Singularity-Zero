"""Screenshot capture module for visual documentation of live hosts.

Uses headless Chromium-based browsers to capture screenshots of target
hosts for inclusion in pipeline reports.
"""

import shutil
from pathlib import Path
from typing import Any

from src.core.logging.pipeline_logging import emit_warning
from src.core.models import Config
from src.pipeline.storage import ensure_dir
from src.pipeline.tools import RetryPolicy, build_retry_policy, run_command


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


def _capture_single(
    url: str,
    browser: str,
    screenshot_dir: Path,
    run_dir: Path,
    settings: dict[str, Any],
    retry_policy: RetryPolicy,
) -> dict[str, Any]:
    """Capture a screenshot for a single URL."""
    destination = screenshot_dir / f"{safe_name_from_url(url)}.png"
    command = [
        browser,
        "--headless",
        "--disable-gpu",
        "--hide-scrollbars",
        f"--window-size={settings.get('window_size', '1440,900')}",
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

    return {
        "url": url,
        "status": status,
        "file": str(destination.relative_to(run_dir)) if destination.exists() else "",
        "error": error,
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

    captures: list[dict[str, Any]] = []
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(
                _capture_single, url, browser, screenshot_dir, run_dir, settings, retry_policy
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
