"""Browser-based runtime detection.

Re-exports the public surface of the headless DOM probe and provides a
shim that lets other detection modules import it lazily without paying
the Playwright import cost at module-load time.
"""

from __future__ import annotations

from typing import Any

from src.detection.browser.runtime_browser import (
    DOMMutationRecord,
    RuntimeDetectionResult,
    analyze,
    analyze_async,
    findings_from_response,
    static_analyze,
)

__all__ = [
    "DOMMutationRecord",
    "RuntimeDetectionResult",
    "analyze",
    "analyze_async",
    "findings_from_response",
    "static_analyze",
]


def is_headless_available() -> bool:
    """Return True when Playwright is importable."""

    from src.detection.browser import runtime_browser as _runtime

    return getattr(_runtime, "async_playwright", None) is not None


def get_instrumentation_script() -> str:
    """Return the DOM instrumentation script (for tests and reuse)."""

    from src.detection.browser import runtime_browser as _runtime

    return _runtime._INSTRUMENTATION_SCRIPT  # noqa: SLF001


def get_interaction_templates() -> tuple[tuple[str, str], ...]:
    """Return the default user interaction templates."""

    from src.detection.browser import runtime_browser as _runtime

    return tuple(_runtime._INTERACTION_TEMPLATES)  # noqa: SLF001


def probe_url(
    url: str,
    *,
    html: str | None = None,
    force_mode: str | None = None,
    timeout_seconds: float = 12.0,
) -> dict[str, Any]:
    """Run a runtime probe and return a dict with mode, error, and findings."""

    result: RuntimeDetectionResult = analyze(
        url,
        html=html,
        force_mode=force_mode,
        timeout_seconds=timeout_seconds,
    )
    return {
        "url": result.url,
        "mode": result.mode,
        "error": result.error,
        "mutations": [m.to_dict() for m in result.mutations],
        "static_findings": list(result.static_findings),
    }
