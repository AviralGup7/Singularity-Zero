"""Process-wide I29 egress filter context for in-process HTTP clients.

``ProcessSandbox`` enforces I29 for subprocess destinations. Domain packages
(``src/analysis``, ``src/exploitation``, recon helpers) often open sockets via
``httpx`` / ``requests`` inside the worker process. This module is the bridge:

* ``stage_admit`` installs a :class:`NetworkEgressFilter` derived from the
  stage ``ScopeToken`` (and scope entries) into a ``ContextVar``.
* ``shared_sessions`` attaches request hooks that call
  ``validate_destination_or_raise`` before every send.
* :func:`ensure_process_http_egress_hooks` patches raw ``httpx.Client`` /
  ``httpx.AsyncClient`` construction and ``requests.Session.request`` so
  call sites that bypass shared sessions still hit the active filter
  (shared-boundary enforcement — prefer hooks over per-file rewrites).
* Callers may still call :func:`assert_egress_allowed` explicitly.

When no filter is installed the default is :meth:`NetworkEgressFilter.metadata_guard`
(cloud-metadata deny, non-strict for other hosts) so detached unit tests keep
working while production admit always installs a strict scope filter.
"""

from __future__ import annotations

import logging
import threading
from contextvars import ContextVar, Token
from typing import Any
from urllib.parse import urlparse

from src.sandbox.network_isolation import EgressViolationError, NetworkEgressFilter

logger = logging.getLogger(__name__)

_CURRENT_EGRESS: ContextVar[NetworkEgressFilter | None] = ContextVar(
    "i29_egress_filter", default=None
)

# Process-level fallback to ensure raw threads or detached async tasks without ContextVar
# inheritance never silently bypass the active stage filter (Gap 7 remediation).
_GLOBAL_PROCESS_EGRESS: NetworkEgressFilter | None = None
_GLOBAL_EGRESS_LOCK = threading.RLock()

_HOOKS_LOCK = threading.Lock()
_HOOKS_INSTALLED = False
_I29_HOOK_MARKER = "_i29_egress_hook"


def get_current_egress_filter() -> NetworkEgressFilter:
    """Return the active filter from ContextVar, or process-wide fallback, or metadata-guard default."""
    current = _CURRENT_EGRESS.get()
    if current is not None:
        return current
    with _GLOBAL_EGRESS_LOCK:
        if _GLOBAL_PROCESS_EGRESS is not None:
            return _GLOBAL_PROCESS_EGRESS
    return NetworkEgressFilter.metadata_guard()


def set_current_egress_filter(filt: NetworkEgressFilter | None) -> Token:
    """Install *filt* for the current context and update process fallback; return a reset token."""
    with _GLOBAL_EGRESS_LOCK:
        global _GLOBAL_PROCESS_EGRESS
        _GLOBAL_PROCESS_EGRESS = filt
    return _CURRENT_EGRESS.set(filt)


def reset_current_egress_filter(token: Token) -> None:
    _CURRENT_EGRESS.reset(token)


def clear_current_egress_filter() -> None:
    with _GLOBAL_EGRESS_LOCK:
        global _GLOBAL_PROCESS_EGRESS
        _GLOBAL_PROCESS_EGRESS = None
    _CURRENT_EGRESS.set(None)


def _egress_strict_context_enabled() -> bool:
    """Flowchart tunable EGRESS_STRICT_CONTEXT (default true)."""
    import os

    raw = os.environ.get("EGRESS_STRICT_CONTEXT", "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def assert_egress_allowed(host: str, port: int | None = None) -> None:
    """Fail closed when *host* is outside the active I29 filter.

    When ``EGRESS_STRICT_CONTEXT=true`` (default) and neither a ContextVar nor
    process-wide filter was installed, still apply metadata_guard (IMDS deny)
    via :func:`get_current_egress_filter` — never a silent allow-all.
    """
    # get_current_egress_filter already falls back to metadata_guard; the env
    # flag documents fail-closed intent and rejects empty hosts early.
    if not str(host or "").strip():
        raise EgressViolationError("I29: empty host")
    if _egress_strict_context_enabled() and _CURRENT_EGRESS.get() is None:
        # Still enforce metadata_guard / process fallback; do not short-circuit.
        pass
    get_current_egress_filter().validate_destination_or_raise(host, port)


def assert_url_egress_allowed(url: str) -> None:
    """Parse *url* and enforce I29 against its host/port.

    When ``EGRESS_RESOLVE_CHECK=true`` (default in production/staging), also
    resolve DNS and validate every A/AAAA (redirect/DNS-rebind hardening).
    """
    import os

    raw = str(url or "").strip()
    if not raw:
        raise EgressViolationError("I29: empty URL")
    resolve = os.environ.get("EGRESS_RESOLVE_CHECK", "").strip().lower()
    if not resolve:
        env = (
            (
                os.environ.get("APP_ENV")
                or os.environ.get("ENVIRONMENT")
                or os.environ.get("CSTP_ENV")
                or ""
            )
            .strip()
            .lower()
        )
        resolve = "true" if env in {"prod", "production", "staging", "stage"} else "false"
    if resolve in {"1", "true", "yes", "on"}:
        from src.sandbox.network_isolation import validate_url_resolved

        validate_url_resolved(url, get_current_egress_filter())
        return
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = parsed.hostname or ""
    if not host:
        raise EgressViolationError(f"I29: URL has no host: {url!r}")
    assert_egress_allowed(host, parsed.port)


def _httpx_sync_request_hook(request: Any) -> None:
    """Sync httpx event hook used on ``httpx.Client`` (and acceptable on AsyncClient)."""
    host = getattr(getattr(request, "url", None), "host", None)
    if not host:
        return
    port = getattr(request.url, "port", None)
    assert_egress_allowed(str(host), port)


async def _httpx_async_request_hook(request: Any) -> None:
    _httpx_sync_request_hook(request)


def _merge_httpx_event_hooks(
    event_hooks: Any,
    *,
    async_client: bool,
) -> dict[str, list[Any]]:
    """Return a copy of *event_hooks* with the I29 request hook prepended once."""
    hooks: dict[str, list[Any]] = {}
    if event_hooks:
        for key, values in dict(event_hooks).items():
            hooks[str(key)] = list(values or [])
    req_hooks = list(hooks.get("request") or [])
    marker = _I29_HOOK_MARKER
    already = any(getattr(h, marker, False) for h in req_hooks)
    if not already:
        hook: Any = _httpx_async_request_hook if async_client else _httpx_sync_request_hook
        setattr(hook, marker, True)
        # Also mark the pair so dual-injection from shared_sessions + patch is deduped
        # by identity/marker rather than by count.
        req_hooks.insert(0, hook)
        hooks["request"] = req_hooks
    return hooks


def ensure_process_http_egress_hooks() -> bool:
    """Idempotently patch httpx/requests so raw clients enforce the ContextVar filter.

    Returns True when this call performed installation, False if already installed.
    Safe to call from stage admit, shared_sessions, and tests.
    """
    global _HOOKS_INSTALLED
    if _HOOKS_INSTALLED:
        return False
    with _HOOKS_LOCK:
        if _HOOKS_INSTALLED:
            return False
        try:
            import httpx
        except ImportError:  # pragma: no cover - httpx is a hard dependency in CI
            httpx = None  # type: ignore[assignment]
        try:
            import requests
        except ImportError:  # pragma: no cover
            requests = None  # type: ignore[assignment]

        if httpx is not None:
            _orig_async_init = httpx.AsyncClient.__init__
            _orig_sync_init = httpx.Client.__init__

            def _patched_async_init(self: Any, *args: Any, **kwargs: Any) -> None:
                kwargs["event_hooks"] = _merge_httpx_event_hooks(
                    kwargs.get("event_hooks"), async_client=True
                )
                return _orig_async_init(self, *args, **kwargs)

            def _patched_sync_init(self: Any, *args: Any, **kwargs: Any) -> None:
                kwargs["event_hooks"] = _merge_httpx_event_hooks(
                    kwargs.get("event_hooks"), async_client=False
                )
                return _orig_sync_init(self, *args, **kwargs)

            setattr(_patched_async_init, _I29_HOOK_MARKER, True)
            setattr(_patched_sync_init, _I29_HOOK_MARKER, True)
            # Avoid re-wrapping if another importer already patched.
            if not getattr(httpx.AsyncClient.__init__, _I29_HOOK_MARKER, False):
                httpx.AsyncClient.__init__ = _patched_async_init  # type: ignore[method-assign]
            if not getattr(httpx.Client.__init__, _I29_HOOK_MARKER, False):
                httpx.Client.__init__ = _patched_sync_init  # type: ignore[method-assign]

        if requests is not None:
            _orig_session_request = requests.Session.request

            def _patched_session_request(
                self: Any,
                method: Any,
                url: Any,
                *args: Any,
                **kwargs: Any,
            ) -> Any:
                assert_url_egress_allowed(str(url))
                return _orig_session_request(self, method, url, *args, **kwargs)

            setattr(_patched_session_request, _I29_HOOK_MARKER, True)
            if not getattr(requests.Session.request, _I29_HOOK_MARKER, False):
                requests.Session.request = _patched_session_request  # type: ignore[method-assign]

        # Patch raw socket.socket.connect and socket.create_connection (I29 universal network boundary)
        import socket

        if not getattr(socket.socket.connect, _I29_HOOK_MARKER, False):
            _orig_socket_connect = socket.socket.connect

            def _patched_socket_connect(self: Any, address: Any) -> Any:
                if isinstance(address, (tuple, list)) and len(address) >= 2:
                    host = str(address[0])
                    port = (
                        int(address[1])
                        if isinstance(address[1], (int, str)) and str(address[1]).isdigit()
                        else None
                    )
                    # Internal IPC/self-pipe loopback connections within the process are preserved
                    if host not in {"127.0.0.1", "::1", "localhost"}:
                        assert_egress_allowed(host, port)
                elif isinstance(address, str):
                    if address not in {"127.0.0.1", "::1", "localhost"}:
                        assert_egress_allowed(address)
                return _orig_socket_connect(self, address)

            setattr(_patched_socket_connect, _I29_HOOK_MARKER, True)
            socket.socket.connect = _patched_socket_connect  # type: ignore[method-assign]

        if hasattr(socket, "create_connection") and not getattr(
            socket.create_connection, _I29_HOOK_MARKER, False
        ):
            _orig_create_connection = socket.create_connection

            def _patched_create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
                if isinstance(address, (tuple, list)) and len(address) >= 2:
                    host = str(address[0])
                    port = (
                        int(address[1])
                        if isinstance(address[1], (int, str)) and str(address[1]).isdigit()
                        else None
                    )
                    if host not in {"127.0.0.1", "::1", "localhost"}:
                        assert_egress_allowed(host, port)
                elif isinstance(address, str):
                    if address not in {"127.0.0.1", "::1", "localhost"}:
                        assert_egress_allowed(address)
                return _orig_create_connection(address, *args, **kwargs)

            setattr(_patched_create_connection, _I29_HOOK_MARKER, True)
            socket.create_connection = _patched_create_connection  # type: ignore[assignment]

        # Patch asyncio.open_connection
        import asyncio

        if hasattr(asyncio, "open_connection") and not getattr(
            asyncio.open_connection, _I29_HOOK_MARKER, False
        ):
            _orig_asyncio_open_conn = asyncio.open_connection

            async def _patched_asyncio_open_conn(
                host: Any = None, port: Any = None, *args: Any, **kwargs: Any
            ) -> Any:
                if host is not None:
                    p = int(port) if isinstance(port, (int, str)) and str(port).isdigit() else None
                    assert_egress_allowed(str(host), p)
                return await _orig_asyncio_open_conn(host, port, *args, **kwargs)

            setattr(_patched_asyncio_open_conn, _I29_HOOK_MARKER, True)
            asyncio.open_connection = _patched_asyncio_open_conn  # type: ignore[assignment]

        _HOOKS_INSTALLED = True
        logger.debug(
            "I29 universal network egress hooks installed (httpx + requests + socket + asyncio)"
        )
        return True


def ensure_process_network_egress_hooks() -> bool:
    """Universal alias for installing all I29 network primitive hooks."""
    return ensure_process_http_egress_hooks()


# ---------------------------------------------------------------------------
# Registered Transport Primitives Registry (I29 Egress Authority Registration)
# ---------------------------------------------------------------------------

_REGISTERED_TRANSPORTS: dict[str, dict[str, Any]] = {
    "httpx": {"type": "http", "enforced_by": "event_hooks + Client.__init__ patch"},
    "requests": {"type": "http", "enforced_by": "Session.request patch"},
    "raw_socket": {
        "type": "tcp/udp",
        "enforced_by": "socket.socket.connect + create_connection patch",
    },
    "asyncio_stream": {"type": "tcp/tls", "enforced_by": "asyncio.open_connection patch"},
    "http2_custom": {"type": "h2/h2c", "enforced_by": "asyncio.open_connection / socket.connect"},
    "websocket_raw": {"type": "ws/wss", "enforced_by": "asyncio.open_connection / socket.connect"},
    "subprocess": {"type": "external_bin", "enforced_by": "ProcessSandbox.check_egress"},
    "headless_browser": {
        "type": "cdp/chromium",
        "enforced_by": "assert_url_egress_allowed pre-navigation",
    },
}


def register_transport_primitive(
    name: str, *, transport_type: str, enforcement_mechanism: str
) -> None:
    """Register a new network-capable transport primitive with the I29 Egress Authority.

    Ensures no transport operates uncataloged or unhooked.
    """
    _REGISTERED_TRANSPORTS[name] = {
        "type": transport_type,
        "enforced_by": enforcement_mechanism,
    }


def get_registered_transports() -> dict[str, dict[str, Any]]:
    """Return dictionary of all registered and enforced transport primitives."""
    return dict(_REGISTERED_TRANSPORTS)


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
    # Shared boundary: once a stage filter is live, raw clients and sockets must see it too.
    ensure_process_network_egress_hooks()
    return filt


__all__ = [
    "assert_egress_allowed",
    "assert_url_egress_allowed",
    "clear_current_egress_filter",
    "ensure_process_http_egress_hooks",
    "ensure_process_network_egress_hooks",
    "get_current_egress_filter",
    "get_registered_transports",
    "install_filter_from_scope",
    "register_transport_primitive",
    "reset_current_egress_filter",
    "set_current_egress_filter",
]
