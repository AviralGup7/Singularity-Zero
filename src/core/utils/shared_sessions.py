"""Shared HTTP session and connection pooling.

Provides process-wide singleton httpx.AsyncClient and requests.Session instances
with configurable connection pools. Avoids creating new clients per request.

This module is the CANONICAL source for all HTTP client instances in the pipeline.
Other modules (http_utils.py, fast_path.py) should obtain clients from here rather
than creating their own, to prevent duplicated connection pools, socket exhaustion,
and inconsistent retry/timeout behavior.

Usage:
    from src.core.utils.shared_sessions import (
        get_async_client,
        get_shared_async_client,
        get_shared_sync_session,
        get_shared_boto3_client,
    )

    # New canonical API — caches by (verify_ssl, follow_redirects)
    client = get_async_client(verify_ssl=True, follow_redirects=True)

    # Legacy API — returns the same default client
    client = get_shared_async_client()

    session = get_shared_sync_session()
    s3 = get_shared_boto3_client("s3", region_name="us-east-1")
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any

import httpx
import requests

logger = logging.getLogger(__name__)

# --- Async httpx client (keyed singleton) ---

_async_clients: dict[tuple[bool, bool], httpx.AsyncClient] = {}
_async_clients_lock = threading.Lock()

_DEFAULT_MAX_CONNECTIONS = 100
_DEFAULT_MAX_KEEPALIVE = 20
_DEFAULT_KEEPALIVE_EXPIRY = 30.0

# Bug #20: Single cleanup authority flag — prevents double cleanup from
# both FastAPI lifespan and lifecycle manager.
_cleanup_done = False
_cleanup_lock = threading.Lock()


def get_async_client(
    verify_ssl: bool = True,
    follow_redirects: bool = True,
    timeout: float = 30.0,
    max_connections: int = _DEFAULT_MAX_CONNECTIONS,
    max_keepalive: int = _DEFAULT_MAX_KEEPALIVE,
) -> httpx.AsyncClient:
    """Return a process-wide shared httpx.AsyncClient keyed by config.

    Clients are cached by (verify_ssl, follow_redirects) to prevent
    duplicated connection pools and socket exhaustion. Subsequent calls
    with the same config return the same client instance.
    """
    key = (verify_ssl, follow_redirects)
    client = _async_clients.get(key)
    if client is not None and not client.is_closed:
        return client

    with _async_clients_lock:
        client = _async_clients.get(key)
        if client is not None and not client.is_closed:
            return client

        client = httpx.AsyncClient(
            verify=verify_ssl,
            follow_redirects=follow_redirects,
            timeout=timeout,
            limits=httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max_keepalive,
                keepalive_expiry=_DEFAULT_KEEPALIVE_EXPIRY,
            ),
        )
        _async_clients[key] = client
        logger.debug(
            "Created shared httpx.AsyncClient (verify=%s, redirects=%s, max_conn=%d)",
            verify_ssl,
            follow_redirects,
            max_connections,
        )
        return client


def get_shared_async_client(
    verify_ssl: bool = True,
    follow_redirects: bool = True,
    timeout: float = 30.0,
    max_connections: int = _DEFAULT_MAX_CONNECTIONS,
    max_keepalive: int = _DEFAULT_MAX_KEEPALIVE,
) -> httpx.AsyncClient:
    """Return a process-wide shared httpx.AsyncClient.

    Legacy API — delegates to get_async_client(). New code should use
    get_async_client() directly.
    """
    return get_async_client(
        verify_ssl=verify_ssl,
        follow_redirects=follow_redirects,
        timeout=timeout,
        max_connections=max_connections,
        max_keepalive=max_keepalive,
    )


def _try_close_client_sync(client: httpx.AsyncClient, context: str) -> None:
    """Best-effort synchronous close of an async client.

    Handles two cases:
    1. Running event loop → schedule as a task AND wait for completion
       with a timeout to prevent connection leaks during shutdown
    2. Non-running loop or no loop → close in a dedicated thread with its
       own event loop

    Bug #21: During shutdown, if the main loop is closing, we do NOT
    create a temporary event loop — we let the OS clean up the sockets.
    Creating temp loops during shutdown causes transport mismatch warnings
    and can interfere with the main loop's teardown.

    Bug #6: Improved shutdown robustness — the close task now handles
    CancelledError (which occurs when the loop stops during shutdown)
    and the wait timeout is extended to 10s to give pending operations
    more time to complete gracefully.
    """
    try:
        coro = client.aclose()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            close_done = threading.Event()
            close_error: Exception | None = None

            async def _close_and_signal() -> None:
                nonlocal close_error
                try:
                    await coro
                except asyncio.CancelledError:
                    close_error = RuntimeError("Client close cancelled during shutdown")
                except Exception as exc:
                    close_error = exc
                finally:
                    close_done.set()

            loop.create_task(_close_and_signal())
            # Bug #6: Extended timeout from 5s to 10s for more graceful shutdown
            close_done.wait(timeout=10.0)
            if not close_done.is_set():
                logger.debug("%s: close task did not complete within 10s timeout", context)
            elif close_error:
                logger.debug("%s: close task raised: %s", context, close_error)
        else:
            # Bug #21: Only create a temp loop if we're NOT in shutdown.
            # During atexit/interpreter teardown, creating new event loops
            # causes transport mismatch and "Event loop is closed" warnings.
            import sys

            if sys.is_finalizing():
                logger.debug("%s: skipping temp event loop during interpreter shutdown", context)
                return

            def _close_in_thread() -> None:
                new_loop = asyncio.new_event_loop()
                try:
                    new_loop.run_until_complete(coro)
                finally:
                    new_loop.close()

            t = threading.Thread(target=_close_in_thread, daemon=True, name=f"close-{context}")
            t.start()
            t.join(timeout=10.0)
            if t.is_alive():
                logger.debug("%s: close thread did not finish within timeout", context)
    except RuntimeError as exc:
        logger.debug("%s: event loop unavailable during shutdown: %s", context, exc)
    except Exception as exc:
        logger.warning("%s: failed to close async client: %s", context, exc)


def close_async_client(verify_ssl: bool = True, follow_redirects: bool = True) -> None:
    """Close and remove a specific async client by config key."""
    key = (verify_ssl, follow_redirects)
    with _async_clients_lock:
        client = _async_clients.pop(key, None)
    if client is not None and not client.is_closed:
        _try_close_client_sync(client, "close_async_client")


def close_all_async_clients() -> None:
    """Close all cached async clients. Called at process exit and during shutdown."""
    with _cleanup_lock:
        global _cleanup_done
        if _cleanup_done:
            return
        _cleanup_done = True

    with _async_clients_lock:
        clients = list(_async_clients.values())
        _async_clients.clear()
    for client in clients:
        if not client.is_closed:
            _try_close_client_sync(client, "close_all_async_clients")


async def async_close_all_clients() -> None:
    """Async-safe shutdown: close all cached clients from within a running event loop.

    Use this during FastAPI lifespan shutdown. This is the PREFERRED shutdown
    path — it directly awaits each client.aclose() without temp event loops.
    """
    with _cleanup_lock:
        global _cleanup_done
        if _cleanup_done:
            return
        _cleanup_done = True

    with _async_clients_lock:
        clients = list(_async_clients.values())
        _async_clients.clear()
    for client in clients:
        if not client.is_closed:
            try:
                await client.aclose()
            except Exception as exc:
                logger.debug("Failed to close async client during async shutdown: %s", exc)


# --- Sync requests.Session (thread-local singleton) ---

_thread_local = threading.local()

# Bug #23: Track all created sessions so cleanup can find them.
# Previously, cleanup scanned _sessions (never populated), causing leaks.
_tracked_sessions: list[requests.Session] = []
_tracked_sessions_lock = threading.Lock()


def get_shared_sync_session() -> requests.Session:
    """Return a thread-local shared requests.Session with connection pooling.

    Each thread gets its own session to avoid thread-safety issues,
    but sessions are reused within a thread.
    """
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=3,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        _thread_local.session = session
        # Bug #23: Track the session so cleanup can find it
        with _tracked_sessions_lock:
            _tracked_sessions.append(session)
    return session


# --- Shared boto3 sessions/clients ---

_BOTO3_CLIENT_TTL_SECONDS: float = 3600.0  # 1 hour

_boto3_sessions: dict[str, Any] = {}
_boto3_clients: dict[tuple[str, str | None], tuple[Any, float]] = {}
_boto3_lock = threading.Lock()


def get_shared_boto3_client(
    service_name: str,
    region_name: str | None = None,
    endpoint_url: str | None = None,
) -> Any:
    """Return a shared boto3 client for the given service.

    Clients are cached by (service_name, region_name) with a TTL to avoid
    holding stale connections indefinitely. Expired entries are evicted
    on access.
    """
    if not _boto3_available():
        raise ImportError("boto3 is required. Install with: pip install boto3")

    import boto3

    cache_key = (service_name, region_name)
    now = time.monotonic()

    with _boto3_lock:
        entry = _boto3_clients.get(cache_key)
        if entry is not None:
            client, created_at = entry
            if now - created_at < _BOTO3_CLIENT_TTL_SECONDS:
                return client
            _boto3_clients.pop(cache_key, None)

        kwargs: dict[str, Any] = {}
        if region_name:
            kwargs["region_name"] = region_name
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url

        client = boto3.client(service_name, **kwargs)
        _boto3_clients[cache_key] = (client, now)
        logger.debug("Created shared boto3 client for %s (region=%s)", service_name, region_name)
        return client


def _boto3_available() -> bool:
    try:
        import boto3  # noqa: F401

        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Cleanup and lifecycle registration
# ---------------------------------------------------------------------------


def _cleanup_shared_sessions() -> None:
    """Clean up shared sessions at process exit.

    Bug #20: This is the ONLY cleanup path for the lifecycle manager.
    It delegates to close_all_async_clients() which has its own
    _cleanup_done guard, preventing double execution.
    """
    close_all_async_clients()

    # Bug #23: Close tracked thread-local sessions
    with _tracked_sessions_lock:
        sessions = list(_tracked_sessions)
        _tracked_sessions.clear()
    for session in sessions:
        try:
            session.close()
        except Exception as exc:
            logger.warning("Failed to close shared session: %s", exc, exc_info=True)


# Bug #22: Registration happens via a function call, not at import time.
# The module-level _register_with_lifecycle() call is kept for backward
# compatibility but is now idempotent.
_lifecycle_registered = False


def _register_with_lifecycle() -> None:
    """Register cleanup with the lifecycle manager.

    Bug #22: Uses a flag to prevent duplicate registration when the
    module is reloaded or imported multiple times.
    """
    global _lifecycle_registered
    if _lifecycle_registered:
        return
    try:
        from src.core.lifecycle import get_lifecycle_manager

        get_lifecycle_manager().register_shutdown(
            "shared_sessions",
            _cleanup_shared_sessions,
            after=["unified_cache_refresh"],
        )
        _lifecycle_registered = True
    except ImportError:
        pass


_register_with_lifecycle()


__all__ = [
    "get_async_client",
    "get_shared_async_client",
    "get_shared_sync_session",
    "get_shared_boto3_client",
    "close_async_client",
    "close_all_async_clients",
    "async_close_all_clients",
]
