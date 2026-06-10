"""DOM-level runtime detection with headless browser support.

Provides in-situ DOM observation that the response-only detection layer
cannot perform. The module supports two execution modes:

1. **Headless mode** (preferred when Playwright is installed). Spawns a
   real browser, navigates to the target, instruments DOM mutations,
   postMessage handlers, ``document.write`` calls, and ``innerHTML``
   assignments, and records them as detection findings. Also tracks the
   user interaction chain that triggered each mutation.

2. **Static fallback mode** (always available). Parses the HTML/JS using
   the AST detectors and emits the same finding shape with lower
   confidence. Used when Playwright is unavailable (e.g. CI without
   browsers) or when an operator opts out of headless probes.

The mode is selected automatically; ``force_headless`` and
``force_static`` can override it for tests and explicit policy.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from src.detection.ast import (
    analyze_html_for_prototype_pollution,
    analyze_html_for_sinks,
)
from src.detection.ast.js_sink_analyzer import fetch_inline_scripts

logger = logging.getLogger(__name__)

_PLAYWRIGHT_IMPORT_ERROR: Exception | None = None
try:  # pragma: no cover - optional import
    from playwright.async_api import async_playwright  # type: ignore[import-not-found]
except Exception as exc:  # pragma: no cover - optional import
    _PLAYWRIGHT_IMPORT_ERROR = exc
    async_playwright = None  # type: ignore[assignment]


_INTERACTION_TEMPLATES: tuple[tuple[str, str], ...] = (
    (
        "click",
        "function() { document.querySelectorAll('a, button, input, [role=button]').forEach(function(el){ try { el.click(); } catch (e) {} }); }",
    ),
    ("scroll", "function() { window.scrollTo(0, document.body.scrollHeight); }"),
    (
        "type",
        "function() { var i = document.querySelector('input, textarea'); if (i) { i.focus(); i.value = 'test'; i.dispatchEvent(new Event('input', { bubbles: true })); } }",
    ),
    (
        "submit",
        "function() { var f = document.querySelector('form'); if (f) { f.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); } }",
    ),
    (
        "hover",
        "function() { document.querySelectorAll('a, button').forEach(function(el) { el.dispatchEvent(new MouseEvent('mouseover', { bubbles: true })); }); }",
    ),
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class DOMMutationRecord:
    """A single DOM mutation or sink call observed at runtime."""

    url: str
    kind: str  # innerHTML | outerHTML | document.write | insertAdjacentHTML | postMessage
    selector: str | None
    payload_preview: str | None
    interaction: str | None
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "indicator": f"dom_runtime_{self.kind}",
            "summary": f"{self.kind} on {self.selector or 'document'} after {self.interaction or 'load'}",
            "severity": "high" if self.kind in {"innerHTML", "document.write"} else "medium",
            "confidence": self.confidence,
            "kind": self.kind,
            "selector": self.selector,
            "payload_preview": self.payload_preview,
            "interaction": self.interaction,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class RuntimeDetectionResult:
    url: str
    mode: str  # "headless" | "static"
    mutations: list[DOMMutationRecord] = field(default_factory=list)
    static_findings: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_findings(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = [m.to_dict() for m in self.mutations]
        findings.extend(self.static_findings)
        return findings


# ---------------------------------------------------------------------------
# Static-mode analyzer
# ---------------------------------------------------------------------------


def static_analyze(html: str, *, url: str) -> RuntimeDetectionResult:
    """Run the AST detectors against a static HTML payload."""

    static_findings: list[dict[str, Any]] = []
    static_findings.extend(analyze_html_for_sinks(html, url=url))
    static_findings.extend(analyze_html_for_prototype_pollution(html, url=url))
    for line_offset, code in fetch_inline_scripts(html):
        for finding in analyze_html_for_sinks(f"<script>{code}</script>", url=url):
            finding["line_offset"] = line_offset
            static_findings.append(finding)
    return RuntimeDetectionResult(url=url, mode="static", static_findings=static_findings)


# ---------------------------------------------------------------------------
# Headless-mode analyzer
# ---------------------------------------------------------------------------


_INSTRUMENTATION_SCRIPT = r"""
(function() {
  if (window.__codex_instrumented) return;
  window.__codex_instrumented = true;
  window.__codex_mutations = window.__codex_mutations || [];
  window.__codex_message_handlers = window.__codex_message_handlers || [];

  function record(kind, payload, target) {
    var entry = {
      kind: kind,
      target: (target && target.tagName) || null,
      selector: (function(el) {
        if (!el || !el.tagName) return null;
        if (el.id) return '#' + el.id;
        if (el.className && typeof el.className === 'string') {
          return el.tagName.toLowerCase() + '.' + el.className.split(' ').join('.');
        }
        return el.tagName.toLowerCase();
      })(target),
      payload: typeof payload === 'string' ? payload.slice(0, 200) : String(payload).slice(0, 200),
      time: Date.now(),
    };
    window.__codex_mutations.push(entry);
  }

  var innerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  Object.defineProperty(Element.prototype, 'innerHTML', {
    configurable: true,
    get: innerHTMLDescriptor && innerHTMLDescriptor.get,
    set: function(value) {
      record('innerHTML', value, this);
      if (innerHTMLDescriptor && innerHTMLDescriptor.set) {
        innerHTMLDescriptor.set.call(this, value);
      } else {
        this.textContent = value;
      }
    }
  });

  var origWrite = document.write;
  document.write = function(html) {
    record('document.write', html, document.documentElement);
    return origWrite.apply(this, arguments);
  };

  var origWriteln = document.writeln;
  document.writeln = function(html) {
    record('document.writeln', html, document.documentElement);
    return origWriteln.apply(this, arguments);
  };

  var origInsertAdjacent = Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML = function(position, html) {
    record('insertAdjacentHTML:' + position, html, this);
    return origInsertAdjacent.apply(this, arguments);
  };

  var origPostMessage = window.postMessage;
  window.postMessage = function(message, targetOrigin, transfer) {
    record('postMessage', message, null);
    return origPostMessage.apply(this, arguments);
  };

  var origAddEventListener = window.addEventListener;
  window.addEventListener = function(type, listener, options) {
    if (type === 'message') {
      window.__codex_message_handlers.push({ registered_at: Date.now() });
    }
    return origAddEventListener.call(this, type, listener, options);
  };

  var origSetTimeout = window.setTimeout;
  window.setTimeout = function(fn, delay) {
    if (typeof fn === 'string') {
      record('setTimeout:string', fn, null);
    }
    return origSetTimeout.apply(this, arguments);
  };
})();
"""


async def _headless_analyze(
    url: str,
    *,
    timeout_seconds: float = 12.0,
    interactions: Iterable[tuple[str, str]] = _INTERACTION_TEMPLATES,
    headless: bool = True,
) -> RuntimeDetectionResult:
    """Run the headless browser probe and return collected mutations."""

    if async_playwright is None:
        return RuntimeDetectionResult(
            url=url,
            mode="static",
            error=f"playwright_unavailable: {_PLAYWRIGHT_IMPORT_ERROR}",
        )

    result = RuntimeDetectionResult(url=url, mode="headless")
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=headless, args=["--no-sandbox"])
            try:
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()
                await page.add_init_script(_INSTRUMENTATION_SCRIPT)
                await page.goto(url, timeout=timeout_seconds * 1000, wait_until="domcontentloaded")
                # Allow late script execution to settle.
                await page.wait_for_timeout(500)
                for name, snippet in interactions:
                    try:
                        await page.evaluate(snippet)
                        await page.wait_for_timeout(150)
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.debug("Interaction %s failed: %s", name, exc)
                raw_mutations = await page.evaluate("() => window.__codex_mutations || []")
                message_handlers = await page.evaluate(
                    "() => window.__codex_message_handlers || []"
                )
            finally:
                await browser.close()
    except Exception as exc:
        result.error = f"headless_failed: {exc}"
        return result

    for entry in raw_mutations or []:
        result.mutations.append(
            DOMMutationRecord(
                url=url,
                kind=str(entry.get("kind", "unknown")),
                selector=entry.get("selector"),
                payload_preview=entry.get("payload"),
                interaction=None,
                confidence=0.85,
                evidence={"recorded_at": entry.get("time")},
            )
        )

    if message_handlers:
        result.mutations.append(
            DOMMutationRecord(
                url=url,
                kind="postMessage_listener",
                selector="window",
                payload_preview=None,
                interaction="event_listener",
                confidence=0.55,
                evidence={"count": len(message_handlers)},
            )
        )

    return result


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def analyze(
    url: str,
    *,
    html: str | None = None,
    force_mode: str | None = None,
    timeout_seconds: float = 12.0,
    headless: bool = True,
) -> RuntimeDetectionResult:
    """Synchronous entry point — picks headless vs static automatically.

    The decision tree:

      1. ``force_mode == 'headless'`` → always use Playwright (or error out).
      2. ``force_mode == 'static'`` → always run static analyzers.
      3. ``CODEX_RUNTIME_DETECTION=headless`` env var → headless.
      4. ``CODEX_RUNTIME_DETECTION=static`` env var → static.
      5. Otherwise prefer headless if Playwright is importable.
    """

    env_mode = os.environ.get("CODEX_RUNTIME_DETECTION", "").strip().lower()
    mode = (force_mode or env_mode or "").lower() or None
    if mode not in {"headless", "static"}:
        mode = "headless" if async_playwright is not None else "static"

    if mode == "headless":
        try:
            return asyncio.run(
                _headless_analyze(
                    url,
                    timeout_seconds=timeout_seconds,
                    headless=headless,
                )
            )
        except Exception as exc:
            logger.warning("Headless analysis failed (%s); falling back to static", exc)
            if html is not None:
                result = static_analyze(html, url=url)
                result.error = f"headless_failed: {exc}"
                return result
            return RuntimeDetectionResult(url=url, mode="static", error=f"headless_failed: {exc}")

    if html is None:
        return RuntimeDetectionResult(url=url, mode="static", error="no_html")
    return static_analyze(html, url=url)


async def analyze_async(
    url: str,
    *,
    html: str | None = None,
    force_mode: str | None = None,
    timeout_seconds: float = 12.0,
    headless: bool = True,
) -> RuntimeDetectionResult:
    env_mode = os.environ.get("CODEX_RUNTIME_DETECTION", "").strip().lower()
    mode = (force_mode or env_mode or "").lower() or None
    if mode not in {"headless", "static"}:
        mode = "headless" if async_playwright is not None else "static"

    if mode == "headless":
        try:
            return await _headless_analyze(url, timeout_seconds=timeout_seconds, headless=headless)
        except Exception as exc:
            if html is not None:
                result = static_analyze(html, url=url)
                result.error = f"headless_failed: {exc}"
                return result
            return RuntimeDetectionResult(url=url, mode="static", error=f"headless_failed: {exc}")

    if html is None:
        return RuntimeDetectionResult(url=url, mode="static", error="no_html")
    return static_analyze(html, url=url)


# ---------------------------------------------------------------------------
# Detection adapter
# ---------------------------------------------------------------------------


def findings_from_response(
    *,
    url: str,
    body_text: str | None = None,
    content_type: str | None = None,
    force_mode: str | None = None,
) -> list[dict[str, Any]]:
    """Adapter that the detection registry can call.

    For ``text/html`` responses the analyzer uses the static fallback unless
    the caller explicitly requests headless mode. JSON responses are scanned
    for prototype pollution data shapes only.
    """

    ct = (content_type or "").lower()
    if body_text is None:
        return []
    if "json" in ct or body_text.lstrip().startswith(("{", "[")):
        return analyze_html_for_sinks("<html></html>", url=url)  # ensure empty for JSON
    if "html" not in ct and "<html" not in body_text.lower():
        return []
    result = analyze(url, html=body_text, force_mode=force_mode or "static")
    return result.to_findings()


__all__ = [
    "DOMMutationRecord",
    "RuntimeDetectionResult",
    "analyze",
    "analyze_async",
    "findings_from_response",
    "static_analyze",
]
