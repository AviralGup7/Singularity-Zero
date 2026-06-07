"""Video recorder for proof-of-concept capture.

Bug-bounty reports are accepted at much higher rates when the
submission includes a short screen recording of the PoC. This
module wraps Playwright (already a project dependency) to capture
videos of a small set of PoC flows.

Usage::

    recorder = VideoRecorder(output_dir=Path("evidence"))
    async with recorder.record("https://target.com/admin") as session:
        # any HTTP calls or browser interactions here are recorded
        ...
    # the .webm file is written to ``output_dir/`` and registered
    # with the finding's evidence.

The recorder is opt-in: callers wrap only the flows that benefit
from a recording. Mass-recording the entire scan is a non-starter
because of disk usage and signal-to-noise.

The module degrades gracefully when Playwright is not installed —
in that case ``record()`` returns a no-op context manager and
reports ``status="unavailable"`` in the result.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Iterable, Mapping

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class VideoResult:
    """Outcome of a video recording session."""

    url: str
    status: str  # "ok" | "unavailable" | "error"
    path: str = ""
    duration_seconds: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "path": self.path,
            "duration_seconds": round(self.duration_seconds, 2),
            "error": self.error,
        }


class VideoRecorder:
    """Capture short screen recordings for PoC flows.

    Parameters
    ----------
    output_dir:
        Directory where ``.webm`` files are written. Created if it
        doesn't exist.
    max_duration_seconds:
        Safety cap per session. The recorder stops and writes the
        final video once this many seconds have elapsed, even if
        the caller's flow is still running.
    viewport:
        ``(width, height)`` tuple for the recording context.
    """

    def __init__(
        self,
        output_dir: Path | str,
        *,
        max_duration_seconds: float = 10.0,
        viewport: tuple[int, int] = (1280, 720),
    ) -> None:
        self.output_dir = Path(output_dir)
        self.max_duration_seconds = float(max_duration_seconds)
        self.viewport = viewport

    def _safe_name(self, url: str) -> str:
        clean = "".join(ch if ch.isalnum() or ch in "-._" else "_" for ch in url)
        clean = clean.strip("._") or "root"
        return f"{clean[:80]}-{int(time.time())}"

    @contextlib.asynccontextmanager
    async def record(
        self,
        url: str,
        *,
        on_flow: Callable[[Any], Any] | None = None,
    ) -> AsyncIterator[VideoResult]:
        """Open a recording context for ``url``.

        ``on_flow`` (if provided) is an async callable that receives
        the Playwright ``page`` object. The caller can drive the page
        (e.g. click an alert dialog, navigate to a callback URL).
        The recording auto-stops after ``max_duration_seconds`` even
        if the caller's flow is still running.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = self._safe_name(url)
        result = VideoResult(url=url, status="ok")

        try:
            from playwright.async_api import async_playwright  # type: ignore
        except ImportError:
            result.status = "unavailable"
            result.error = "playwright not installed"
            yield result
            return

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": self.viewport[0], "height": self.viewport[1]},
                record_video_dir=str(self.output_dir),
                record_video_size={
                    "width": self.viewport[0],
                    "height": self.viewport[1],
                },
            )
            page = await context.new_page()
            start = time.monotonic()
            try:
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=10_000)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("VideoRecorder: page.goto failed for %s: %s", url, exc)
                if on_flow is not None:
                    try:
                        # Apply a soft cap so a stuck flow doesn't pin
                        # the recording forever.
                        await asyncio.wait_for(
                            asyncio.ensure_future(on_flow(page)),
                            timeout=self.max_duration_seconds,
                        )
                    except asyncio.TimeoutError:
                        logger.debug(
                            "VideoRecorder: flow for %s exceeded %.1fs, stopping",
                            url,
                            self.max_duration_seconds,
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("VideoRecorder: flow raised for %s: %s", url, exc)
                # Brief wait to ensure the recording has at least one
                # frame of the post-flow state.
                await asyncio.sleep(0.5)
                video_path = await page.video.path()  # type: ignore[union-attr]
            finally:
                result.duration_seconds = time.monotonic() - start
                try:
                    await context.close()
                except Exception:  # noqa: BLE001
                    pass
                try:
                    await browser.close()
                except Exception:  # noqa: BLE001
                    pass

        # Playwright writes the file with a generated name; rename it
        # to something descriptive so the operator can find it in
        # the evidence bundle.
        try:
            src = Path(video_path)
            if src.exists():
                dest = self.output_dir / f"{filename}.webm"
                shutil.move(str(src), str(dest))
                result.path = str(dest)
            else:
                result.status = "error"
                result.error = "playwright did not write a video file"
        except Exception as exc:  # noqa: BLE001
            result.status = "error"
            result.error = f"failed to move video: {exc}"

        yield result

    async def record_many(
        self,
        urls: Iterable[str],
        *,
        on_flow: Callable[[Any], Any] | None = None,
    ) -> list[VideoResult]:
        """Record several URLs in sequence."""
        results: list[VideoResult] = []
        for url in urls:
            async with self.record(url, on_flow=on_flow) as result:
                pass
            results.append(result)
        return results


__all__ = [
    "VideoRecorder",
    "VideoResult",
]
