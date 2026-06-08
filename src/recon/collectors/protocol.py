"""Unified ``CollectorProvider`` protocol.

Every URL collector (wayback, commoncrawl, otx, urlscan, crawler,
simplecrawler, …) and the subdomain sources are all "providers" that
share the same high-level contract:

* given a list of host roots, return a set of discovered URLs
* carry a :class:`~src.recon.collectors.types.CollectorMeta` describing
  what happened (status, durations, error counts, etc.)

Historically the URL collectors lived in
:mod:`src.recon.collectors.providers.*` and exposed ``collect_for_hosts``
+ ``iter_for_hosts``, while the subdomain sources in
:mod:`src.recon.sources.*` exposed async ``query_<source>`` functions
returning ``set[str]``.  This module defines the *minimum* surface that
both families must satisfy so the aggregators can dispatch uniformly
and so we can layer health/circuit-breaker logic on top.

Adapters
========

The :func:`adapt_subdomain_source` helper bridges a ``query_<source>``
async function (returning ``set[str]``) into a synchronous
:func:`collect_for_hosts` / :func:`iter_for_hosts` pair that matches
this protocol, so a single aggregator can drive both URL collectors
and subdomain sources when needed.
"""

from __future__ import annotations

from collections.abc import Callable, Generator, Iterable
from typing import Any, Protocol, runtime_checkable

from src.recon.collectors.types import CollectorMeta
from src.recon.common import run_async_in_sync_context

# A "host list" is any iterable of strings (we normalise inside each
# provider to be defensive against ``set``/``list``/``tuple``/generator
# inputs).
HostList = Iterable[str]


@runtime_checkable
class CollectorProvider(Protocol):
    """The minimum contract every in-house collector must satisfy.

    Implementations MUST return a ``(set[str], CollectorMeta)`` pair
    from :func:`collect_for_hosts` and SHOULD expose
    :func:`iter_for_hosts` for streaming aggregators that need to
    interleave per-host results.
    """

    name: str

    def collect_for_hosts(
        self,
        hosts: HostList,
        **kwargs: Any,
    ) -> tuple[set[str], CollectorMeta]: ...

    def iter_for_hosts(
        self,
        hosts: HostList,
        **kwargs: Any,
    ) -> Generator[tuple[str, set[str], CollectorMeta], None, CollectorMeta]: ...


# Subdomain source alias: async ``(host) -> set[str]`` callable.
SubdomainAsyncSource = Callable[[str], Any]


def adapt_subdomain_source(
    name: str,
    async_func: SubdomainAsyncSource,
    *,
    timeout_seconds: int = 30,
) -> CollectorProvider:
    """Adapt an async ``query_<source>`` function to the ``CollectorProvider`` protocol.

    The returned object exposes ``collect_for_hosts`` and
    ``iter_for_hosts`` and is drop-in compatible with the URL
    collectors when wired through :class:`ProviderSpec`.
    """

    class _Adapter:
        def __init__(self) -> None:
            self.name = name

        def collect_for_hosts(
            self, hosts: HostList, **_kwargs: Any
        ) -> tuple[set[str], CollectorMeta]:
            from src.recon.collectors.types import CollectorStatus

            hosts_list = [str(h).strip() for h in hosts if h]
            if not hosts_list:
                return (
                    set(),
                    CollectorMeta(
                        status=CollectorStatus.EMPTY,
                        new_urls=0,
                        hosts_scanned=0,
                        provider_name=name,
                    ),
                )
            discovered: set[str] = set()
            errors = 0
            for host in hosts_list:
                try:
                    res = run_async_in_sync_context(async_func(host))
                    if isinstance(res, (set, frozenset, list, tuple)):
                        discovered.update(str(u) for u in res if u)
                except Exception:  # noqa: BLE001
                    errors += 1
            return (
                discovered,
                CollectorMeta(
                    status=CollectorStatus.OK if discovered else CollectorStatus.EMPTY,
                    new_urls=len(discovered),
                    errors=errors,
                    hosts_scanned=len(hosts_list),
                    provider_name=name,
                ),
            )

        def iter_for_hosts(
            self, hosts: HostList, **_kwargs: Any
        ) -> Generator[tuple[str, set[str], CollectorMeta], None, CollectorMeta]:
            from src.recon.collectors.types import CollectorStatus

            hosts_list = [str(h).strip() for h in hosts if h]
            if not hosts_list:
                return CollectorMeta(
                    status=CollectorStatus.EMPTY,
                    new_urls=0,
                    hosts_scanned=0,
                    provider_name=name,
                )
            total_new = 0
            total_errors = 0
            for host in hosts_list:
                host_urls: set[str] = set()
                host_error = 0
                try:
                    res = run_async_in_sync_context(async_func(host))
                    if isinstance(res, (set, frozenset, list, tuple)):
                        host_urls = {str(u) for u in res if u}
                except Exception:  # noqa: BLE001
                    host_error = 1
                total_new += len(host_urls)
                total_errors += host_error
                yield host, host_urls, CollectorMeta(
                    status=CollectorStatus.OK if host_urls else CollectorStatus.EMPTY,
                    new_urls=len(host_urls),
                    errors=host_error,
                    hosts_scanned=1,
                    provider_name=name,
                )
            return CollectorMeta(
                status=CollectorStatus.OK if total_new else CollectorStatus.EMPTY,
                new_urls=total_new,
                errors=total_errors,
                hosts_scanned=len(hosts_list),
                provider_name=name,
            )

    return _Adapter()


__all__ = [
    "CollectorProvider",
    "HostList",
    "SubdomainAsyncSource",
    "adapt_subdomain_source",
]
