"""Tests for :mod:`src.recon.collectors.protocol` (CollectorProvider + adapter)."""

from __future__ import annotations

from src.recon.collectors import protocol
from src.recon.collectors.protocol import (
    CollectorProvider,
    adapt_subdomain_source,
)
from src.recon.collectors.types import CollectorMeta, CollectorStatus


class _AsyncSource:
    """Mimic a query_<source> async function returning ``set[str]``."""

    def __init__(self, value=set()):
        self.value = value
        self.calls: list[str] = []

    async def __call__(self, host: str):
        self.calls.append(host)
        return self.value


class TestAdaptSubdomainSource:
    def test_returns_object_named_after_source(self) -> None:
        src = _AsyncSource()
        provider = adapt_subdomain_source("custom", src)
        assert provider.name == "custom"

    def test_collect_for_hosts_returns_set_and_meta(self) -> None:
        src = _AsyncSource(value={"a.example.com", "b.example.com"})
        provider = adapt_subdomain_source("custom", src)
        urls, meta = provider.collect_for_hosts(["example.com", "api.example.com"])
        assert urls == {"a.example.com", "b.example.com"}
        assert meta.provider_name == "custom"
        assert meta.status == CollectorStatus.OK
        assert meta.hosts_scanned == 2

    def test_collect_for_hosts_empty_hosts(self) -> None:
        src = _AsyncSource()
        provider = adapt_subdomain_source("custom", src)
        urls, meta = provider.collect_for_hosts([])
        assert urls == set()
        assert meta.status == CollectorStatus.EMPTY
        assert meta.hosts_scanned == 0

    def test_iter_for_hosts_yields_per_host(self) -> None:
        src = _AsyncSource(value={"x.example.com"})
        provider = adapt_subdomain_source("custom", src)
        gen = provider.iter_for_hosts(["a.example.com", "b.example.com"])
        yielded = []
        aggregate_meta: CollectorMeta | None = None
        try:
            while True:
                yielded.append(next(gen))
        except StopIteration as stop:
            aggregate_meta = stop.value  # type: ignore[assignment]
        # 2 hosts × 1 url each
        assert {h for h, _, _ in yielded} == {"a.example.com", "b.example.com"}
        assert aggregate_meta is not None
        assert isinstance(aggregate_meta, CollectorMeta)
        assert aggregate_meta.hosts_scanned == 2

    def test_iter_for_hosts_empty_hosts(self) -> None:
        src = _AsyncSource()
        provider = adapt_subdomain_source("custom", src)
        gen = provider.iter_for_hosts([])
        try:
            next(gen)
        except StopIteration as stop:
            assert stop.value.status == CollectorStatus.EMPTY

    def test_collect_for_hosts_handles_async_exception(self) -> None:
        class _Boom:
            async def __call__(self, host: str):
                raise RuntimeError("network down")

        provider = adapt_subdomain_source("custom", _Boom())
        urls, meta = provider.collect_for_hosts(["example.com"])
        assert urls == set()
        assert meta.errors == 1
        assert meta.status == CollectorStatus.EMPTY  # no successful urls

    def test_provider_satisfies_protocol(self) -> None:
        src = _AsyncSource()
        provider = adapt_subdomain_source("custom", src)
        # ``isinstance`` against a runtime-checkable Protocol should succeed
        # for a duck-typed adapter.
        assert isinstance(provider, CollectorProvider)


class TestProviderModuleSurface:
    def test_module_exports(self) -> None:
        assert hasattr(protocol, "CollectorProvider")
        assert hasattr(protocol, "adapt_subdomain_source")
        assert hasattr(protocol, "HostList")
        assert hasattr(protocol, "SubdomainAsyncSource")
