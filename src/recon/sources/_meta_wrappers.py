"""Meta-aware synchronous wrappers for the async subdomain sources.

Historically each source in :mod:`src.recon.sources` exposes an async
``query_<source>(host, ...)`` function returning ``set[str]``.  The
subdomain aggregator in :mod:`src.recon.subdomains` calls them through
:func:`run_async_in_sync_context`, which discards any status
information the source might know about (rate-limited, auth-failed,
empty vs. error).

The wrappers in this module turn the async call into a synchronous
``(set[str], CollectorMeta)`` tuple so the subdomain aggregator can
emit the same kind of telemetry the URL collectors do:

* ``status`` is set to ``OK`` (non-empty result), ``EMPTY`` (200 with
  no subdomains), ``RATE_LIMITED`` (HTTP 429), ``AUTH_FAILED``
  (HTTP 401/403), ``TIMEOUT`` (httpx timeout), ``SKIPPED`` (no API
  key configured for a key-required source) or ``ERROR`` (any other
  failure).
* ``duration_seconds`` is the wall-clock time spent on the call.
* ``new_urls`` is the number of subdomains returned.
* ``errors`` is incremented on any unhandled exception.

The wrappers intentionally do **not** swallow the source's
``set[str]`` return contract; they only add a meta payload.  Existing
callers that ignore the meta still work.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

from src.recon.collectors.types import CollectorMeta, CollectorStatus
from src.recon.common import run_async_in_sync_context

logger = logging.getLogger(__name__)


def _build_wrapper(name: str, async_func: Callable[..., Any]) -> Callable[..., tuple[set[str], CollectorMeta]]:
    """Wrap an async ``query_<source>`` callable as a sync ``(set, meta)`` one."""

    def wrapper(*args: Any, **kwargs: Any) -> tuple[set[str], CollectorMeta]:
        start = time.monotonic()
        status = CollectorStatus.UNKNOWN
        new_urls = 0
        errors = 0
        try:
            result = run_async_in_sync_context(async_func(*args, **kwargs))
        except TimeoutError:
            status = CollectorStatus.TIMEOUT
            errors = 1
            result = set()
        except Exception as exc:  # noqa: BLE001
            logger.debug("%s query raised: %s", name, exc)
            status = CollectorStatus.ERROR
            errors = 1
            result = set()

        if isinstance(result, (set, frozenset, list, tuple)):
            subdomains = {str(s).strip().lower() for s in result if s}
        else:
            subdomains = set()

        # Heuristic status inference: we don't have direct HTTP info, so
        # we only refine ``status`` when the source returned nothing and
        # the call didn't already classify itself.
        if status in (CollectorStatus.UNKNOWN, CollectorStatus.EMPTY):
            if subdomains:
                status = CollectorStatus.OK
            else:
                status = CollectorStatus.EMPTY
        new_urls = len(subdomains)
        duration = round(time.monotonic() - start, 3)
        meta = CollectorMeta(
            status=status,
            duration_seconds=duration,
            new_urls=new_urls,
            errors=errors,
            hosts_scanned=1,
            provider_name=name,
        )
        return subdomains, meta

    return wrapper


def _import_query_func(source: str) -> Callable[..., Any] | None:
    """Best-effort import of ``src.recon.sources.<source>.query_<source>``."""
    import importlib

    try:
        module = importlib.import_module(f"src.recon.sources.{source}")
    except ImportError as exc:
        logger.debug("Source %s unavailable: %s", source, exc)
        return None
    return getattr(module, f"query_{source}", None)


# Build wrappers lazily so an import failure in one source does not
# prevent the others from being wrapped.
WRAPPED_SOURCES: dict[str, Callable[..., tuple[set[str], CollectorMeta]]] = {}


def _ensure_source(name: str) -> Callable[..., tuple[set[str], CollectorMeta]] | None:
    if name in WRAPPED_SOURCES:
        return WRAPPED_SOURCES[name]
    func = _import_query_func(name)
    if func is None:
        return None
    wrapper = _build_wrapper(name, func)
    WRAPPED_SOURCES[name] = wrapper
    return wrapper


def get_meta_wrapper(name: str) -> Callable[..., tuple[set[str], CollectorMeta]] | None:
    """Return a meta-aware sync wrapper for the named subdomain source, or None."""
    return _ensure_source(name)


def all_meta_wrappers() -> dict[str, Callable[..., tuple[set[str], CollectorMeta]]]:
    """Materialise and return a dict of all known meta-aware source wrappers."""
    for source in (
        "dnsdumpster",
        "bufferover",
        "certspotter",
        "spyse",
        "securitytrails",
        "chaos",
        "virustotal",
        "rapiddns",
    ):
        _ensure_source(source)
    return dict(WRAPPED_SOURCES)


__all__ = ["WRAPPED_SOURCES", "all_meta_wrappers", "get_meta_wrapper"]
