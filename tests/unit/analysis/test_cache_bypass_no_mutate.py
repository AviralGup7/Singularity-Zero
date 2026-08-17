"""Regression: cache-bypass must not mutate the caller's header dict."""

from __future__ import annotations

import pytest

from src.analysis.checks.active.cache_bypass import CacheBypassMiddleware


@pytest.mark.unit
def test_process_request_strips_conditional_headers_case_insensitive() -> None:
    mw = CacheBypassMiddleware()
    original = {
        "If-None-Match": '"abc"',
        "If-Modified-Since": "Wed, 21 Oct 2015 07:28:00 GMT",
        "Authorization": "Bearer x",
        "Accept": "application/json",
    }
    snapshot = dict(original)
    out = mw.process_request(original)
    assert original == snapshot
    assert "If-None-Match" not in out
    assert "If-Modified-Since" not in out
    assert out["Authorization"] == "Bearer x"
    assert out["Accept"] == "application/json"


@pytest.mark.unit
def test_add_cache_busting_does_not_mutate_input() -> None:
    mw = CacheBypassMiddleware()
    original = {"Accept": "text/html"}
    out = mw.add_cache_busting(original)
    assert original == {"Accept": "text/html"}
    assert "Cache-Control" not in original
    assert out["Cache-Control"] == "no-cache, no-store, must-revalidate"
    assert out["Pragma"] == "no-cache"
    assert out["Expires"] == "0"
    assert out["Accept"] == "text/html"


@pytest.mark.unit
def test_full_bypass_handles_none_and_empty() -> None:
    mw = CacheBypassMiddleware()
    assert mw.process_request(None) == {}
    out = mw.process_request_with_cache_bypass(None)
    assert out["Cache-Control"].startswith("no-cache")
    assert "If-None-Match" not in out
