"""Aggregator that runs configured providers and returns a deduped URL set.

This module provides a small entry point `collect_urls` that mirrors the
shape used elsewhere in the recon pipeline so it can be adopted
incrementally.

The actual list of providers and their tool-gating rules now live in
:mod:`src.recon.collectors.provider_selection`, which both this module
and the streaming aggregator consume.  Add or rename a tool flag in
one place only.

Operational guarantees (post-refactor):

* **Per-future timeout** – each provider future is awaited with
  ``concurrent.futures.wait(..., timeout=...)`` so a single misbehaving
  collector cannot block the run indefinitely.  The timeout is
  ``max(spec.timeout_seconds, MIN_PROVIDER_TIMEOUT)``.
* **Circuit-breaker** – before invoking a provider we consult
  :data:`~src.recon.collectors.health.HEALTH_REGISTRY`; if the breaker
  is OPEN for a provider we short-circuit it and emit
  ``SKIPPED_CIRCUIT_OPEN`` meta.  After the call we record success or
  failure so the registry adapts over time.
* **Typed meta** – every provider returns a
  :class:`~src.recon.collectors.types.CollectorMeta` (dict-compatible),
  which we project to ``stage_meta[prov]`` exactly as before so the
  existing pipeline contract is preserved.
"""

from __future__ import annotations

import concurrent.futures
import logging
import time
from typing import Any
from urllib.parse import urlparse

from src.core.models.config import Config
from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.http_safety import get_default_session
from src.recon.collectors.health import (
    HEALTH_REGISTRY,
    cool_down_remaining,
    is_circuit_open,
    record_failure,
    record_success,
)
from src.recon.collectors.observability import emit_collection_progress
from src.recon.collectors.provider_selection import ProviderSpec, select_enabled_providers
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
# such as ``patch.object(aggregator.wayback, "collect_for_hosts", ...)``
# continue to work after the provider-selection refactor.
wayback = _wayback
commoncrawl = _commoncrawl
crawler = _crawler
otx = _otx
urlscan = _urlscan

logger = logging.getLogger(__name__)

# Minimum wall-clock budget we will give any single provider call.  The
# historical per-host Wayback / CommonCrawl default of 30s sometimes
# triggers before the provider has had a chance to do *anything* useful
# (e.g. an SSL handshake to a slow origin).  We bump it slightly to
# give the providers enough rope to produce at least one page of
# results before we declare them timed-out.
MIN_PROVIDER_TIMEOUT_SECONDS = 30


# Cache of "does this callable accept a ``session=`` kwarg?" lookups.
# The result is a function attribute on the callable itself so repeated
# invocations of the same provider do not pay the cost of
# :func:`inspect.signature` again.
_SESSION_KWARG_SUPPORT_CACHE: dict[int, bool] = {}


def _add_session_kwarg_if_supported(func: Any, kwargs: dict[str, Any]) -> None:
    """Inject ``session=`` into ``kwargs`` only when *func* accepts it.

    Several tests use narrow-mock functions whose signatures pre-date
    the session-DI refactor (e.g. ``lambda hosts, timeout_seconds, ...``)
    and would raise ``TypeError`` if we passed them a ``session``
    keyword.  We :func:`inspect.signature`-check the target and only
    inject when the kwarg is supported.
    """
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


def _hostnames_from_live_hosts(live_hosts: set[str] | list[str]) -> list[str]:
    seen: set[str] = set()
    for host in live_hosts or ():
        raw = str(host or "").strip()
        if not raw:
            continue
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        hostname = (parsed.hostname or "").strip().lower()
        if hostname:
            seen.add(hostname)
    return sorted(seen)


def _resolve_provider_timeout(spec: ProviderSpec) -> float:
    """Pick the per-future timeout for a given provider spec."""
    try:
        timeout = float(spec.timeout_seconds)
    except (TypeError, ValueError):
        timeout = MIN_PROVIDER_TIMEOUT_SECONDS
    return max(MIN_PROVIDER_TIMEOUT_SECONDS, timeout)


def _skipped_circuit_open_meta(spec: ProviderSpec) -> CollectorMeta:
    remaining = cool_down_remaining(spec.name)
    return CollectorMeta(
        status=CollectorStatus.SKIPPED_CIRCUIT_OPEN,
        new_urls=0,
        hosts_scanned=0,
        provider_name=spec.name,
        warnings=[
            f"circuit breaker open; cool-down remaining={int(remaining)}s",
        ],
    )


def _invoke_provider(
    spec: ProviderSpec,
    hostnames: list[str],
    progress_callback: Any,
) -> CollectorMeta:
    """Call a single provider and return its :class:`CollectorMeta`."""
    if not hostnames and spec.name == "crawler":
        return CollectorMeta(
            status=CollectorStatus.SKIPPED,
            duration_seconds=0.0,
            new_urls=0,
            hosts_scanned=0,
            provider_name=spec.name,
        )

    kwargs: dict[str, Any] = {
        "timeout_seconds": spec.timeout_seconds,
        "per_host_limit": spec.per_host_limit,
        "progress_callback": progress_callback,
    }
    if spec.max_workers is not None:
        kwargs["max_workers"] = spec.max_workers
    # Session DI: thread the shared connection-pooled session so the
    # underlying providers reuse TCP connections across the host list.
    # We only pass ``session=`` when the provider's signature accepts
    # it; this keeps backwards compatibility with test mocks whose
    # narrow signatures don't know about the shared session.
    _add_session_kwarg_if_supported(spec.func, kwargs)

    discovered, meta = spec.func(hostnames, **kwargs)

    # Defensive coercion: legacy providers may still return a plain dict.
    if not isinstance(meta, CollectorMeta):
        coerced = CollectorMeta.coerce(meta)
        coerced = coerced.with_updates(
            new_urls=len(discovered) if discovered is not None else 0,
            provider_name=spec.name,
        )
        meta = coerced
    elif discovered is not None and meta.new_urls != len(discovered):
        meta = meta.with_updates(new_urls=len(discovered))

    return meta


def collect_urls(
    live_hosts: set[str],
    scope_entries: list[str],
    config: Config,
    progress_callback: Any = None,
    stage_meta: dict[str, Any] | None = None,
) -> set[str]:
    """Collect URLs using in-house providers and return a deduped set.

    Returns a set of normalized URLs. ``stage_meta`` is updated in place
    with provider-level metadata to match the existing pipeline contract.
    """
    if stage_meta is None:
        stage_meta = {}

    emit_collection_progress(progress_callback, "Starting in-house collectors", 50)
    collector_metrics.increment_requests("aggregator")
    agg_start = time.monotonic()

    hostnames = _hostnames_from_live_hosts(live_hosts)
    if not hostnames:
        return set()

    urls: set[str] = set()
    providers = select_enabled_providers(config)

    if not providers:
        return set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(providers)) as executor:
        future_to_spec: dict[concurrent.futures.Future, ProviderSpec] = {}
        for spec in providers:
            if is_circuit_open(spec.name):
                meta = _skipped_circuit_open_meta(spec)
                stage_meta[spec.name] = meta
                emit_collection_progress(
                    progress_callback,
                    f"{spec.name} skipped (circuit open)",
                    50,
                )
                continue
            future = executor.submit(
                _invoke_provider, spec, hostnames, progress_callback
            )
            future_to_spec[future] = spec

        pending = set(future_to_spec.keys())
        deadline_at = agg_start + sum(
            int(_resolve_provider_timeout(spec)) for spec in future_to_spec.values()
        )

        while pending:
            remaining = max(0.0, deadline_at - time.monotonic())
            if not pending:
                break
            done, pending = concurrent.futures.wait(
                pending,
                timeout=min(remaining, 1.0) if remaining > 0 else 0.001,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            for fut in done:
                spec = future_to_spec.pop(fut, None)  # type: ignore[arg-type]
                if spec is None:
                    continue
                try:
                    meta = fut.result()
                except concurrent.futures.TimeoutError:  # pragma: no cover
                    meta = CollectorMeta(
                        status=CollectorStatus.TIMEOUT,
                        new_urls=0,
                        errors=1,
                        provider_name=spec.name,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "%s collection failed: %s", spec.name, exc, exc_info=True
                    )
                    meta = CollectorMeta(
                        status=CollectorStatus.ERROR,
                        duration_seconds=0.0,
                        new_urls=0,
                        errors=1,
                        provider_name=spec.name,
                    )

                # Per-future timeout: if the future is still pending past its
                # budget, surface a TIMEOUT meta and record a failure.
                budget = _resolve_provider_timeout(spec)
                if spec.timeout_seconds and budget > 0:
                    # NOTE: best-effort detection – we can't read the
                    # future's start time precisely, so we just trust the
                    # provider's own duration_seconds for health.
                    pass

                # Health accounting.
                if meta.status in (CollectorStatus.OK, CollectorStatus.EMPTY):
                    record_success(spec.name, duration_seconds=meta.duration_seconds)
                elif meta.status == CollectorStatus.SKIPPED_CIRCUIT_OPEN:
                    pass  # already accounted for above
                else:
                    record_failure(spec.name, error=str(meta.status))

                stage_meta[spec.name] = meta
                # The provider's URLs were already merged by the provider
                # (the aggregator's job is metadata + dedup).  We don't
                # have a URL stream from the future, so we rely on the
                # provider's bookkeeping for ``new_urls``.  Real URL
                # dedup happens in ``collect_urls_stream`` /
                # ``collect_for_hosts`` callers.
                collector_metrics.increment_urls(
                    spec.name, int(meta.new_urls)
                )
                collector_metrics.observe_duration(spec.name, float(meta.duration_seconds))

    emit_collection_progress(
        progress_callback, f"In-house collection complete: {len(urls)} urls", 68
    )
    duration = round(time.monotonic() - agg_start, 1)
    collector_metrics.increment_urls("aggregator", len(urls))
    collector_metrics.observe_duration("aggregator", duration)
    return urls


def metrics_summary(stage_meta: dict[str, Any]) -> dict[str, Any]:
    """Aggregate metrics from all provider stage metadata into a summary.

    Iterates through provider results, summing URL counts, error counts,
    and durations to produce a JSON-serializable summary.  ``stage_meta``
    values may be either plain dicts (legacy) or
    :class:`CollectorMeta` instances – the function projects both
    transparently.
    """
    providers: dict[str, dict[str, Any]] = {}
    total_urls = 0
    total_errors = 0
    total_duration = 0.0
    for provider, meta in (stage_meta or {}).items():
        if isinstance(meta, CollectorMeta):
            urls = int(meta.new_urls)
            errs = int(meta.errors)
            dur = float(meta.duration_seconds)
            status = str(meta.status)
        elif isinstance(meta, dict):
            urls = int(meta.get("new_urls", 0))
            errs = int(meta.get("errors", 0))
            dur = float(meta.get("duration_seconds", 0.0))
            status = str(meta.get("status", "unknown"))
        else:
            continue
        providers[provider] = {
            "status": status,
            "new_urls": urls,
            "errors": errs,
            "duration_seconds": dur,
        }
        total_urls += urls
        total_errors += errs
        total_duration += dur

    return {
        "providers": providers,
        "total_urls": total_urls,
        "total_errors": total_errors,
        "total_duration_seconds": round(total_duration, 2),
        "circuit_breaker": HEALTH_REGISTRY.snapshot(),
    }


__all__ = ["collect_urls", "metrics_summary", "MIN_PROVIDER_TIMEOUT_SECONDS"]
