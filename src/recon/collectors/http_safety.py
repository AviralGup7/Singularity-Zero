"""Shared HTTP safety, retry, and session-injection helpers for collectors.

Before this module existed, every provider hand-rolled its own copy of:

* a 60-line ``_is_safe_url`` SSRF guard (scheme allow-list + DNS
  resolution + private/loopback/link-local range checks),
* a ``for attempt in range(...)`` retry loop with backoff + metric
  bookkeeping, and
* a bare ``requests.get(...)`` call with no shared connection pool and
  no way to inject a mock client for testing beyond patching
  ``requests.get`` globally.

The duplication was responsible for a class of bugs where one provider
patched its blocked-network list without the others (e.g. IPv6
loopback) and for the brittle test setup where two providers used the
same ``monkeypatch.setattr("requests.get", ...)`` line and clobbered
each other's expectations.

This module is the single source of truth for those three concerns.
Public entry points:

* :func:`is_safe_url` – raise ``ValueError`` when the target URL fails
  the SSRF policy.  ``check_once`` mode caches successful checks
  per-URL so a hot provider does not re-resolve DNS for every host.
* :func:`safe_get` – issue an HTTP GET that runs through the SSRF
  guard, an injectable ``requests.Session`` (or a module-default), a
  bounded retry loop with exponential backoff, and metric bookkeeping.
  Returns ``None`` after exhausting retries instead of raising so
  providers can fall back to an empty result gracefully.
* :func:`get_default_session` – module-level ``requests.Session`` with
  HTTP connection pooling enabled.  Reused across providers to cut
  TCP setup overhead for the hundreds of sequential requests Wayback
  / CommonCrawl issue across hosts.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

import requests

from src.recon.collectors import metrics as collector_metrics

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SSRF policy
# ---------------------------------------------------------------------------

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
)

# Cache of already-vetted URLs so providers calling ``is_safe_url`` with
# ``check_once=True`` against a fixed API endpoint do not pay the DNS
# cost on every host iteration.  Wayback alone is responsible for
# thousands of redundant ``getaddrinfo`` calls without this cache.
_SAFE_URL_CACHE: set[str] = set()
_SAFE_URL_CACHE_LOCK = threading.Lock()


def is_safe_url(url: str, *, check_once: bool = False) -> None:
    """Raise ``ValueError`` when *url* fails the SSRF policy.

    Args:
        url: Absolute HTTP(S) URL to validate.
        check_once: When ``True``, successful results are cached for
            the lifetime of the process and subsequent calls with the
            same URL short-circuit without re-resolving DNS.  Use this
            for static API endpoints (Wayback CDX, CommonCrawl index,
            OTX domain endpoint, urlscan search) where the value is a
            constant and the cost of repeated DNS lookups is wasteful.

    Raises:
        ValueError: When the scheme is not http(s), DNS resolution
            fails, or any resolved address lands in a private /
            loopback / link-local range.
    """
    if check_once:
        with _SAFE_URL_CACHE_LOCK:
            if url in _SAFE_URL_CACHE:
                return

    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"Disallowed URL scheme: {parsed.scheme!r} (only http/https allowed)")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Cannot parse hostname from URL: {url}")

    try:
        try:
            addr = ipaddress.ip_address(hostname)
            resolved: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [addr]
        except ValueError:
            resolved = []
            for family_info in socket.getaddrinfo(
                hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                proto=socket.IPPROTO_TCP,
            ):
                addr_str = family_info[4][0]
                try:
                    resolved.append(ipaddress.ip_address(addr_str))
                except ValueError:
                    continue
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for {hostname}: {exc}") from exc

    for ip in resolved:
        for network in _BLOCKED_NETWORKS:
            if ip in network:
                raise ValueError(f"URL resolves to blocked address {ip} in {network}: {url}")

    if check_once:
        with _SAFE_URL_CACHE_LOCK:
            _SAFE_URL_CACHE.add(url)


def clear_safe_url_cache() -> None:
    """Invalidate the ``check_once`` cache (test helper)."""
    with _SAFE_URL_CACHE_LOCK:
        _SAFE_URL_CACHE.clear()


# ---------------------------------------------------------------------------
# Shared session for connection-pooling
# ---------------------------------------------------------------------------

_DEFAULT_SESSION: requests.Session | None = None
_DEFAULT_SESSION_LOCK = threading.Lock()


def _build_default_session() -> requests.Session:
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=10,
        pool_maxsize=50,
        max_retries=0,  # we manage retries ourselves in safe_get
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.setdefault("User-Agent", "target-specific-pipeline/2.0")
    return session


def get_default_session() -> requests.Session:
    """Return a process-wide :class:`requests.Session` with pooling enabled.

    Providers should pass this (or an injected alternative) to
    :func:`safe_get` rather than relying on the module-level
    ``requests.get`` helper, which creates a fresh TCP connection for
    every call.
    """
    global _DEFAULT_SESSION
    if _DEFAULT_SESSION is None:
        with _DEFAULT_SESSION_LOCK:
            if _DEFAULT_SESSION is None:
                _DEFAULT_SESSION = _build_default_session()
    return _DEFAULT_SESSION


def reset_default_session() -> None:
    """Drop the cached default session (test helper)."""
    global _DEFAULT_SESSION
    with _DEFAULT_SESSION_LOCK:
        if _DEFAULT_SESSION is not None:
            try:
                _DEFAULT_SESSION.close()
            except Exception:  # pragma: no cover - defensive  # noqa: S110
                pass
        _DEFAULT_SESSION = None


import atexit as _atexit

_atexit.register(reset_default_session)


# ---------------------------------------------------------------------------
# Retrying GET with metric bookkeeping
# ---------------------------------------------------------------------------

DEFAULT_MAX_RETRIES = 2
DEFAULT_BACKOFF_SECONDS = 0.25


class SafeGetResult:
    """Lightweight wrapper around a :class:`requests.Response` plus telemetry.

    Returned by :func:`safe_get` so callers can introspect outcomes
    without re-implementing retry / metrics bookkeeping.

    Attributes:
        response: The successful response, or ``None`` after exhausting
            retries.
        attempts: Number of HTTP attempts actually performed.
        timed_out: ``True`` when at least one attempt raised
            :class:`requests.Timeout` (or its subclass).  Used by the
            aggregator to distinguish transient network hiccups from
            permanent auth failures.
        last_error: String repr of the last exception encountered, or
            ``None`` when the call succeeded.
    """

    __slots__ = ("response", "attempts", "timed_out", "last_error")

    def __init__(
        self,
        response: requests.Response | None,
        attempts: int,
        timed_out: bool,
        last_error: str | None,
    ) -> None:
        self.response = response
        self.attempts = attempts
        self.timed_out = timed_out
        self.last_error = last_error

    @property
    def ok(self) -> bool:
        return self.response is not None and self.response.status_code < 400


def safe_get(
    url: str,
    *,
    provider: str,
    timeout_seconds: int,
    params: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    session: requests.Session | None = None,
    max_retries: int = DEFAULT_MAX_RETRIES,
    backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
    ssrf_check_once: bool = True,
    raise_for_status: bool = True,
) -> SafeGetResult:
    """Perform an SSRF-guarded HTTP GET with a bounded retry loop.

    The function intentionally never raises: it returns a
    :class:`SafeGetResult` with ``response=None`` after exhausting
    retries so the caller can fall back to an empty result set.  This
    matches the historical behaviour of every collector that previously
    inlined this loop and lets the aggregator stay agnostic to network
    failure modes.

    Args:
        url: Absolute URL to fetch.  Subjected to the SSRF check.
        provider: Short provider name used for metric labelling
            (``"wayback"``, ``"otx"`` …).
        timeout_seconds: Per-request timeout, floored to 2 seconds to
            match the historical Wayback / CommonCrawl behaviour.
        params: Optional query-string parameters.
        headers: Optional request headers.
        session: Optional injected session (mock-friendly).  Falls back
            to :func:`get_default_session`.
        max_retries: Number of additional attempts on transient
            failures.  ``max_retries=2`` means up to three total
            attempts (matching the previous Wayback default).
        backoff_seconds: Base for exponential backoff between retries.
        ssrf_check_once: When ``True`` (default), the SSRF check uses
            the per-URL cache so a constant API endpoint is not
            re-validated on every call.
        raise_for_status: When ``True``, treat HTTP 4xx / 5xx as a
            failed attempt.  When ``False``, return the response
            regardless so the caller can inspect the status code.

    Returns:
        :class:`SafeGetResult` describing the outcome.
    """
    timeout = max(2, int(timeout_seconds))
    attempts_budget = max(1, int(max_retries) + 1)
    timed_out = False
    last_error: str | None = None

    # SSRF guard – do this once before the loop so cache hits avoid the
    # cost on every iteration.
    try:
        is_safe_url(url, check_once=ssrf_check_once)
    except ValueError as exc:
        logger.debug("safe_get(%s): SSRF check failed: %s", provider, exc)
        collector_metrics.increment_errors(provider)
        return SafeGetResult(None, 0, False, str(exc))

    # When no session is injected we delegate to the module-level
    # ``requests.get`` helper.  This keeps the historical contract
    # (``monkeypatch.setattr("requests.get", ...)`` patches every call
    # through this helper) and avoids opening a connection pool when
    # the caller has not opted into one.  Injected sessions get the
    # pool-friendly ``Session.get`` path automatically.
    get_callable = session.get if session is not None else requests.get

    # Only pass ``headers``/``params`` kwargs when they are actually
    # provided so unit tests that monkeypatch ``requests.get`` with a
    # narrower signature (``def fake_get(url, params=None, timeout=None)``)
    # continue to work without surprise TypeErrors.
    kwargs: dict[str, Any] = {"timeout": timeout}
    if params:
        kwargs["params"] = dict(params)
    if headers:
        kwargs["headers"] = dict(headers)

    for attempt in range(1, attempts_budget + 1):
        collector_metrics.increment_requests(provider)
        try:
            response = get_callable(url, **kwargs)
        except requests.Timeout as exc:
            timed_out = True
            last_error = repr(exc)
            collector_metrics.increment_errors(provider)
            logger.debug(
                "safe_get(%s): timeout on attempt %d/%d: %s",
                provider,
                attempt,
                attempts_budget,
                exc,
            )
            if attempt < attempts_budget:
                _sleep(backoff_seconds * (2 ** (attempt - 1)))
                continue
            return SafeGetResult(None, attempt, True, last_error)
        except requests.RequestException as exc:  # pragma: no cover - network
            last_error = repr(exc)
            collector_metrics.increment_errors(provider)
            logger.debug(
                "safe_get(%s): request error on attempt %d/%d: %s",
                provider,
                attempt,
                attempts_budget,
                exc,
            )
            if attempt < attempts_budget:
                _sleep(backoff_seconds * (2 ** (attempt - 1)))
                continue
            return SafeGetResult(None, attempt, timed_out, last_error)

        if raise_for_status and response.status_code >= 400:
            last_error = f"HTTP {response.status_code}"
            collector_metrics.increment_errors(provider)
            logger.debug(
                "safe_get(%s): %s on attempt %d/%d",
                provider,
                last_error,
                attempt,
                attempts_budget,
            )
            if attempt < attempts_budget and response.status_code >= 500:
                _sleep(backoff_seconds * (2 ** (attempt - 1)))
                continue
            return SafeGetResult(response, attempt, timed_out, last_error)

        return SafeGetResult(response, attempt, timed_out, None)

    # Defensive: the loop above always returns, this line is unreachable
    # but keeps mypy happy and acts as a backstop.
    return SafeGetResult(None, attempts_budget, timed_out, last_error)


def _sleep(seconds: float) -> None:
    """Sleep helper that swallows the rare interruption error.

    Extracted so tests can monkey-patch it to zero out backoff time
    without having to patch ``time.sleep`` globally and risk breaking
    other code that expects real sleeps.
    """
    try:
        time.sleep(max(0.0, seconds))
    except Exception as exc:  # pragma: no cover - very defensive
        logger.debug("safe_get sleep interrupted: %s", exc)


__all__ = [
    "is_safe_url",
    "clear_safe_url_cache",
    "get_default_session",
    "reset_default_session",
    "safe_get",
    "SafeGetResult",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_BACKOFF_SECONDS",
]
