"""Streaming aggregator for providers.

Yields URLs as providers produce results. This is an incremental,
non-blocking (per provider) streaming model that keeps memory usage
bounded and allows downstream consumers to process results while
collection is still ongoing.

The provider list is sourced from
:mod:`src.recon.collectors.provider_selection` so any change to the
tool-gating rules only has to be made in one place.

Operational guarantees
======================

* **Per-future timeout** – each provider future is awaited via
  ``concurrent.futures.wait(..., timeout=...)`` so a single misbehaving
  collector cannot stall the stream.
* **Circuit-breaker** – providers whose breaker is currently OPEN are
  short-circuited with ``SKIPPED_CIRCUIT_OPEN`` meta and emit zero
  URLs to the downstream consumer.
* **Typed meta** – every provider's return value is coerced to a
  :class:`~src.recon.collectors.types.CollectorMeta` (dict-compatible)
  so the consumer can introspect status, durations, error counts, etc.
"""

from __future__ import annotations

import concurrent.futures
import time
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from src.core.models.config import Config
from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.health import (
    cool_down_remaining,
    is_circuit_open,
    record_failure,
    record_success,
)
from src.recon.collectors.http_safety import get_default_session
from src.recon.collectors.observability import emit_collection_progress
from src.recon.collectors.provider_selection import select_enabled_providers
from src.recon.collectors.providers import (
    commoncrawl as _commoncrawl,
)
from src.recon.collectors.providers import (
    crawler as _crawler,
)
from src.recon.collectors.providers import (
    otx as _otx,
)
from src.recon.collectors.providers import (
    urlscan as _urlscan,
)
from src.recon.collectors.providers import (
    wayback as _wayback,
)
from src.recon.collectors.types import CollectorMeta, CollectorStatus

# Re-export provider modules at module level so existing test patches
# such as ``patch.object(aggregator_stream.wayback, "collect_for_hosts", ...)``
# continue to work after the provider-selection refactor.
wayback = _wayback
commoncrawl = _commoncrawl
crawler = _crawler
otx = _otx
urlscan = _urlscan

MIN_PROVIDER_TIMEOUT_SECONDS = 30

# Cache of "does this callable accept a ``session=`` kwarg?" lookups.
# The result is a function attribute on the callable itself so repeated
# invocations of the same provider do not pay the cost of
# :func:`inspect.signature` again.
_SESSION_KWARG_SUPPORT_CACHE: dict[int, bool] = {}


def _add_session_kwarg_if_supported(func: Any, kwargs: dict[str, Any]) -> None:
    """Inject ``session=`` into ``kwargs`` only when *func* accepts it."""
    if "session" in kwargs:
        return
    key = id(func)
    if key not in _SESSION_KWARG_SUPPORT_CACHE:
        try:
            import inspect

            sig = inspect.signature(func)
            _SESSION_KWARG_SUPPORT_CACHE[key] = "session" in sig.parameters
        except (TypeError, ValueError):
            _SESSION_KWARG_SUPPORT_CACHE[key] = False
    if _SESSION_KWARG_SUPPORT_CACHE[key]:
        kwargs["session"] = get_default_session()


def _resolve_provider_timeout(timeout_seconds: int | None) -> float:
    try:
        t = float(timeout_seconds or 0)
    except (TypeError, ValueError):
        t = 0.0
    return max(MIN_PROVIDER_TIMEOUT_SECONDS, t) if t > 0 else MIN_PROVIDER_TIMEOUT_SECONDS


def collect_urls_stream(
    live_hosts: set[str],
    scope_entries: list[str],
    config: Config,
    progress_callback: Any = None,
    stage_meta: dict[str, Any] | None = None,
) -> Generator[str, None, dict[str, Any]]:
    """Yield normalized URLs discovered by providers and return stage_meta when done.

    Usage:
        stream = collect_urls_stream(...)
        for url in stream:
            handle(url)
        # generator returns stage_meta as StopIteration.value when exhausted
    """
    if stage_meta is None:
        stage_meta = {}

    emit_collection_progress(progress_callback, "Starting streaming in-house collectors", 50)
    collector_metrics.increment_requests("aggregator_stream")
    hostnames = sorted({(h or "").strip() for h in live_hosts if (h or "").strip()})
    if not hostnames:
        return stage_meta

    providers = select_enabled_providers(config)
    if not providers:
        return stage_meta

    seen: set[str] = set()
    start = time.monotonic()
    budget_total = sum(
        int(_resolve_provider_timeout(spec.timeout_seconds)) for spec in providers
    )
    deadline_at = start + budget_total

    with ThreadPoolExecutor(max_workers=max(1, len(providers))) as executor:
        future_to_spec: dict[concurrent.futures.Future, Any] = {}
        for spec in providers:
            if is_circuit_open(spec.name):
                meta = CollectorMeta(
                    status=CollectorStatus.SKIPPED_CIRCUIT_OPEN,
                    new_urls=0,
                    hosts_scanned=0,
                    provider_name=spec.name,
                    warnings=[
                        f"circuit breaker open; cool-down remaining="
                        f"{int(cool_down_remaining(spec.name))}s",
                    ],
                )
                stage_meta[spec.name] = meta
                emit_collection_progress(
                    progress_callback,
                    f"{spec.name} skipped (circuit open)",
                    50,
                )
                continue
            kwargs: dict[str, Any] = {
                "timeout_seconds": spec.timeout_seconds,
                "per_host_limit": spec.per_host_limit,
                "max_workers": min(spec.max_workers or 6, len(hostnames)),
                "progress_callback": progress_callback,
            }
            _add_session_kwarg_if_supported(spec.func, kwargs)
            future_to_spec[executor.submit(spec.func, hostnames, **kwargs)] = spec

        pending = set(future_to_spec.keys())

        while pending:
            remaining = max(0.0, deadline_at - time.monotonic())
            timeout_slice = min(remaining, 1.0) if remaining > 0 else 0.001
            done, pending = concurrent.futures.wait(
                pending,
                timeout=timeout_slice,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for fut in done:
                spec = future_to_spec.pop(fut, None)
                if spec is None:
                    continue
                try:
                    discovered, meta = fut.result()
                except concurrent.futures.TimeoutError:  # pragma: no cover
                    discovered, meta = set(), CollectorMeta(
                        status=CollectorStatus.TIMEOUT,
                        new_urls=0,
                        errors=1,
                        provider_name=spec.name,
                    )
                except Exception:  # noqa: BLE001
                    discovered, meta = set(), CollectorMeta(
                        status=CollectorStatus.ERROR,
                        duration_seconds=0.0,
                        new_urls=0,
                        errors=1,
                        provider_name=spec.name,
                    )

                if not isinstance(meta, CollectorMeta):
                    coerced = CollectorMeta.coerce(meta)
                    meta = coerced.with_updates(
                        new_urls=len(discovered) if discovered else 0,
                        provider_name=spec.name,
                    )
                elif discovered is not None and meta.new_urls != len(discovered):
                    meta = meta.with_updates(new_urls=len(discovered))

                if meta.status in (CollectorStatus.OK, CollectorStatus.EMPTY):
                    record_success(spec.name, duration_seconds=meta.duration_seconds)
                elif meta.status != CollectorStatus.SKIPPED_CIRCUIT_OPEN:
                    record_failure(spec.name, error=str(meta.status))

                stage_meta[spec.name] = meta
                for u in discovered or set():
                    if u and u not in seen:
                        seen.add(u)
                        yield u

    duration = round(time.monotonic() - start, 1)
    collector_metrics.increment_urls("aggregator_stream", len(seen))
    collector_metrics.observe_duration("aggregator_stream", duration)
    emit_collection_progress(
        progress_callback, f"Streaming collectors complete: {len(seen)} urls", 68
    )
    return stage_meta


__all__ = ["collect_urls_stream", "MIN_PROVIDER_TIMEOUT_SECONDS"]
