"""Process-wide I29 egress filter context for in-process HTTP clients.

``ProcessSandbox`` enforces I29 for subprocess destinations. Domain packages
(``src/analysis``, ``src/exploitation``, recon helpers) often open sockets via
``httpx`` / ``requests`` inside the worker process. This module is the bridge:

* ``stage_admit`` installs a :class:`NetworkEgressFilter` derived from the
  stage ``ScopeToken`` (and scope entries) into a ``ContextVar``.
* ``shared_sessions`` attaches request hooks that call
  ``validate_destination_or_raise`` before every send.
* Callers that still construct raw clients should call
  :func:`assert_egress_allowed` (or prefer ``get_async_client``).

When no filter is installed the default is :meth:`NetworkEgressFilter.metadata_guard`
(cloud-metadata deny, non-strict for other hosts) so detached unit tests keep
working while production admit always installs a strict scope filter.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any
from urllib.parse import urlparse

from src.sandbox.network_isolation import EgressViolationError, NetworkEgressFilter

_CURRENT_EGRESS: ContextVar[NetworkEgressFilter | None] = ContextVar(
    "i29_egress_filter", default=None
)


def get_current_egress_filter() -> NetworkEgressFilter:
    """Return the active filter, or the metadata-guard default."""
    current = _CURRENT_EGRESS.get()
    if current is not None:
        return current
    return NetworkEgressFilter.metadata_guard()


def set_current_egress_filter(filt: NetworkEgressFilter | None) -> Token:
    """Install *filt* for the current context; return a reset token."""
    return _CURRENT_EGRESS.set(filt)


def reset_current_egress_filter(token: Token) -> None:
    _CURRENT_EGRESS.reset(token)


def clear_current_egress_filter() -> None:
    _CURRENT_EGRESS.set(None)


def assert_egress_allowed(host: str, port: int | None = None) -> None:
    """Fail closed when *host* is outside the active I29 filter."""
    get_current_egress_filter().validate_destination_or_raise(host, port)


def assert_url_egress_allowed(url: str) -> None:
    """Parse *url* and enforce I29 against its host/port."""
    raw = str(url or "").strip()
    if not raw:
        raise EgressViolationError("I29: empty URL")
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = parsed.hostname or ""
    if not host:
        raise EgressViolationError(f"I29: URL has no host: {url!r}")
    assert_egress_allowed(host, parsed.port)


def install_filter_from_scope(
    *,
    scope_token: Any | None = None,
    scope_entries: Any | None = None,
) -> NetworkEgressFilter:
    """Build + install a filter from ticket scope and/or pipeline entries."""
    filt: NetworkEgressFilter | None = None
    if scope_token is not None and (
        getattr(scope_token, "allowed_domains", None) or getattr(scope_token, "allowed_cidrs", None)
    ):
        filt = NetworkEgressFilter.from_scope_token(scope_token)
    entries_filt = NetworkEgressFilter.from_scope_entries(scope_entries)
    if filt is None:
        filt = entries_filt
    elif entries_filt.allowed_domains:
        # Union domains from both sources; keep strict if either is strict.
        domains = tuple(dict.fromkeys((*filt.allowed_domains, *entries_filt.allowed_domains)))
        cidrs = tuple(dict.fromkeys((*filt.allowed_cidrs, *entries_filt.allowed_cidrs)))
        filt = NetworkEgressFilter(
            allowed_domains=domains,
            allowed_cidrs=cidrs,
            strict=filt.strict or entries_filt.strict,
        )
    set_current_egress_filter(filt)
    return filt


__all__ = [
    "assert_egress_allowed",
    "assert_url_egress_allowed",
    "clear_current_egress_filter",
    "get_current_egress_filter",
    "install_filter_from_scope",
    "reset_current_egress_filter",
    "set_current_egress_filter",
]
