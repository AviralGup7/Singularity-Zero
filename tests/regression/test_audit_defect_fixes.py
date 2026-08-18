"""Regression tests for defects found during a static code audit.

Covers three real bugs:

1. ``_payload_generator.PayloadGenerator.generate`` had a duplicate
   ``elif ctx.context == "html"`` branch (dead code after the initial
   ``if``).  Verified the per-context dispatch is correct and that the
   ``dead`` context is skipped.

2. ``open_redirect_active_probe`` had a dead ``elif`` that re-tested the
   Location-header condition, so ``open_redirect_body_reflection`` could
   never fire.  Now the body branch checks the response *body* for the
   external domain, as the docstring promises.

3. ``ResourcePool.close`` had a dead ``elif hasattr(resource, "close")``,
   so sync-close resources raised ``TypeError`` on ``await resource.close()``.
   Now async and sync ``close()`` are both handled.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from src.analysis.active.injection._context_detector import ReflectionContext
from src.analysis.active.injection._payload_generator import PayloadGenerator
from src.analysis.active.injection.open_redirect import open_redirect_active_probe
from src.core.persistence.transaction import ResourcePool


# ---------------------------------------------------------------------------
# Bug 1: PayloadGenerator per-context dispatch
# ---------------------------------------------------------------------------
class _FakeCache:
    """Minimal stand-in for the analysis-layer response cache."""

    def __init__(self, response: dict[str, Any]) -> None:
        self._response = response
        self.requested: list[str] = []

    def request(self, url: str, **kwargs: Any) -> dict[str, Any]:
        self.requested.append(url)
        return self._response


@pytest.mark.regression
@pytest.mark.parametrize("context", ["html", "attribute", "script", "comment"])
def test_payload_generator_dispatches_each_context_correctly(context: str) -> None:
    """Each reflection context must map to its own vector family exactly once."""
    gen = PayloadGenerator([ReflectionContext(position=0, context=context)], include_evasion=False)
    result = gen.generate()
    assert result, f"expected vectors for context {context!r}"
    for level, entries in result.items():
        assert isinstance(level, int) and 1 <= level <= 10
        for entry in entries:
            assert entry.context == context, (
                f"context {context!r} produced a vector labelled {entry.context!r}"
            )


@pytest.mark.regression
def test_payload_generator_skips_dead_context() -> None:
    """The 'dead' context must produce no vectors."""
    gen = PayloadGenerator([ReflectionContext(position=0, context="dead")], include_evasion=False)
    assert gen.generate() == {}


# ---------------------------------------------------------------------------
# Bug 2: open-redirect body reflection
# ---------------------------------------------------------------------------
@pytest.mark.regression
def test_open_redirect_body_reflection_is_detected() -> None:
    """A body that reflects an external domain must flag body reflection."""
    cache = _FakeCache(
        {
            "status_code": 200,
            "headers": {},  # no Location header
            "body": "You are being redirected to https://evil.com now...",
        }
    )
    urls = [{"url": "https://example.com/page?redirect=https://example.com"}]
    findings = open_redirect_active_probe(urls, cache, limit=10)

    assert findings, "expected at least one open-redirect finding"
    issues = findings[0]["issues"]
    assert "open_redirect_body_reflection" in issues
    assert "open_redirect_location_header" not in issues


@pytest.mark.regression
def test_open_redirect_location_header_still_detected() -> None:
    """The Location-header branch must still fire (guard against regressions)."""
    cache = _FakeCache(
        {
            "status_code": 302,
            "headers": {"Location": "https://evil.com/landing"},
            "body": "",
        }
    )
    urls = [{"url": "https://example.com/page?redirect=https://example.com"}]
    findings = open_redirect_active_probe(urls, cache, limit=10)

    assert findings
    assert "open_redirect_location_header" in findings[0]["issues"]


@pytest.mark.regression
def test_open_redirect_no_reflection_no_finding() -> None:
    """No external domain in header or body must produce no finding."""
    cache = _FakeCache(
        {
            "status_code": 200,
            "headers": {},
            "body": "OK, nothing to see here.",
        }
    )
    urls = [{"url": "https://example.com/page?redirect=https://example.com"}]
    findings = open_redirect_active_probe(urls, cache, limit=10)
    assert findings == []


# ---------------------------------------------------------------------------
# Bug 3: ResourcePool.close with sync vs async close()
# ---------------------------------------------------------------------------
@pytest.mark.regression
def test_resource_pool_close_handles_sync_close() -> None:
    """Sync ``close()`` resources must not raise TypeError during shutdown."""

    class SyncResource:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    async def _run() -> None:
        made: list[SyncResource] = []

        async def factory() -> SyncResource:
            resource = SyncResource()
            made.append(resource)
            return resource

        pool = ResourcePool(factory=factory, min_size=2, max_size=4)
        await pool.initialize()
        await pool.close()
        assert made and all(r.closed for r in made)

    asyncio.run(_run())


@pytest.mark.regression
def test_resource_pool_close_handles_async_close() -> None:
    """Async ``close()`` resources must still be awaited during shutdown."""

    class AsyncResource:
        def __init__(self) -> None:
            self.closed = False

        async def close(self) -> None:
            self.closed = True

    async def _run() -> None:
        made: list[AsyncResource] = []

        async def factory() -> AsyncResource:
            resource = AsyncResource()
            made.append(resource)
            return resource

        pool = ResourcePool(factory=factory, min_size=2, max_size=4)
        await pool.initialize()
        await pool.close()
        assert made and all(r.closed for r in made)

    asyncio.run(_run())
