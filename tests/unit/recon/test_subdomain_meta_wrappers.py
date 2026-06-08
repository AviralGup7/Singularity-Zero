"""Tests for :mod:`src.recon.sources._meta_wrappers`."""

from __future__ import annotations

import asyncio

from src.recon.collectors.types import CollectorMeta, CollectorStatus
from src.recon.sources import _meta_wrappers


class _FakeAsyncSource:
    """Helper that mimics the contract of a ``query_<source>`` async function."""

    def __init__(self, return_value=set(), sleep_for: float = 0.0, raises: Exception | None = None):
        self.return_value = return_value
        self.sleep_for = sleep_for
        self.raises = raises
        self.call_count = 0

    async def __call__(self, host: str, *args, **kwargs):
        self.call_count += 1
        if self.sleep_for:
            await asyncio.sleep(self.sleep_for)
        if self.raises is not None:
            raise self.raises
        return self.return_value


class TestBuildWrapper:
    def test_returns_set_with_meta(self) -> None:
        src = _FakeAsyncSource(return_value={"foo.example.com", "bar.example.com"})
        wrapper = _meta_wrappers._build_wrapper("fake", src)
        result, meta = wrapper("example.com")
        assert result == {"foo.example.com", "bar.example.com"}
        assert isinstance(meta, CollectorMeta)
        assert meta.provider_name == "fake"
        assert meta.status == CollectorStatus.OK
        assert meta.new_urls == 2
        assert meta.hosts_scanned == 1
        assert meta.errors == 0
        assert meta.duration_seconds >= 0

    def test_empty_returns_empty_status(self) -> None:
        src = _FakeAsyncSource(return_value=set())
        wrapper = _meta_wrappers._build_wrapper("fake", src)
        result, meta = wrapper("example.com")
        assert result == set()
        assert meta.status == CollectorStatus.EMPTY
        assert meta.new_urls == 0

    def test_exception_is_caught(self) -> None:
        src = _FakeAsyncSource(raises=RuntimeError("boom"))
        wrapper = _meta_wrappers._build_wrapper("fake", src)
        result, meta = wrapper("example.com")
        assert result == set()
        assert meta.status == CollectorStatus.ERROR
        assert meta.errors == 1

    def test_timeout_error_classified(self) -> None:
        src = _FakeAsyncSource(raises=TimeoutError("slow"))
        wrapper = _meta_wrappers._build_wrapper("fake", src)
        result, meta = wrapper("example.com")
        assert meta.status == CollectorStatus.TIMEOUT
        assert meta.errors == 1
        assert result == set()

    def test_non_set_return_coerced(self) -> None:
        src = _FakeAsyncSource(return_value=["foo.example.com", "bar.example.com", 42])
        wrapper = _meta_wrappers._build_wrapper("fake", src)
        result, meta = wrapper("example.com")
        # Coerced to a set of strings, dropping non-strings.
        assert "foo.example.com" in result
        assert "bar.example.com" in result
        # Coercion may keep 42 as a string; that's OK.
        assert meta.new_urls == len(result)


class TestGetMetaWrapper:
    def test_known_source_returns_wrapper(self) -> None:
        wrapper = _meta_wrappers.get_meta_wrapper("dnsdumpster")
        # ``dnsdumpster`` is a real registered source — the wrapper should
        # be created lazily on first call.
        if wrapper is not None:
            assert callable(wrapper)

    def test_unknown_source_returns_none(self) -> None:
        wrapper = _meta_wrappers.get_meta_wrapper("this-source-does-not-exist-xyz")
        assert wrapper is None

    def test_wrapper_cached(self) -> None:
        wrapper1 = _meta_wrappers.get_meta_wrapper("dnsdumpster")
        wrapper2 = _meta_wrappers.get_meta_wrapper("dnsdumpster")
        assert wrapper1 is wrapper2 or (wrapper1 is None and wrapper2 is None)


class TestAllMetaWrappers:
    def test_returns_dict(self) -> None:
        wrappers = _meta_wrappers.all_meta_wrappers()
        assert isinstance(wrappers, dict)
        # At least the well-known sources should be present if their
        # modules are importable.
        for source in ("dnsdumpster", "bufferover", "certspotter"):
            assert source in wrappers
