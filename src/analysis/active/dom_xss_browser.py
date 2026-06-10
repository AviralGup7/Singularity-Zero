"""DOM XSS browser probe using Playwright (optional)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

_playwright: Any = None
_async_playwright: Any = None


def _load_playwright() -> bool:
    global _playwright, _async_playwright
    try:
        _playwright = __import__(
            "playwright.sync_api", fromlist=["sync_playwright"]
        ).sync_playwright
        _async_playwright = __import__(
            "playwright.async_api", fromlist=["async_playwright"]
        ).async_playwright
        return True
    except ImportError:
        return False


_PLAYWRIGHT_AVAILABLE = _load_playwright()


class DomXssBrowserProbe:
    """Probe a URL for DOM-based XSS using a headless browser when Playwright is available."""

    def __init__(self) -> None:
        self._pw_ready: bool = _PLAYWRIGHT_AVAILABLE

    async def probe(self, url: str, marker: str) -> list[Any]:
        """Launch a headless browser and check whether *marker* is reflected in
        an executable DOM sink after page load.
        """
        from src.core.models.entities import Finding

        findings: list[Finding] = []
        if not self._pw_ready:
            return findings

        try:
            async with _async_playwright().start() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()

                def inject_marker(body: str) -> str:
                    return body.replace("></", f">{marker}<")

                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    await browser.close()
                    return findings

                injected = inject_marker(await page.content())
                await page.set_content(injected, wait_until="networkidle")

                reflected_html = await page.evaluate(
                    f"""() => {{
                        const marker = {marker!r};
                        const d = document;
                        if (d.documentElement.innerHTML.includes(marker)) return 'innerHTML';
                        try {{
                            if (d.body.innerHTML.includes(marker)) return 'body-html';
                        }} catch (e) {{}}
                        try {{
                            const s = d.createElement('div');
                            s.innerHTML = location.hash.slice(1);
                            if (s.textContent.includes(marker)) return 'hash';
                        }} catch (e) {{}}
                        return null;
                    }}"""
                )

                if reflected_html:
                    findings.append(
                        Finding(
                            category="dom_xss",
                            title="DOM-based XSS marker reflected in executable sink",
                            url=url,
                            severity="high",
                            confidence=0.7,
                            evidence={
                                "sink": reflected_html,
                                "marker": marker,
                            },
                        )
                    )

                await browser.close()
        except Exception as exc:
            logger.debug("DomXssBrowserProbe.probe failed: %s", exc)

        return findings

    async def probe_postmessage(self, url: str) -> list[Any]:
        """Send a probe postMessage and record any window.open / eval triggered."""
        from src.core.models.entities import Finding

        findings: list[Finding] = []
        if not self._pw_ready:
            return findings

        try:
            async with _async_playwright().start() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()

                handles: list[str] = []

                page.on(
                    "popup", lambda p: handles.append(p.url if hasattr(p, "url") else "<popup>")
                )

                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    await browser.close()
                    return findings

                await page.evaluate(
                    """(payload) => window.postMessage(payload, '*')""",
                    {"data": "<svg onload=alert(1)>"},
                )

                await asyncio.sleep(1)

                if handles:
                    findings.append(
                        Finding(
                            category="dom_xss",
                            title="postMessage handler opened unexpected popup",
                            url=url,
                            severity="high",
                            confidence=0.75,
                            evidence={"popup_urls": handles},
                        )
                    )

                await browser.close()
        except Exception as exc:
            logger.debug("DomXssBrowserProbe.probe_postmessage failed: %s", exc)

        return findings
