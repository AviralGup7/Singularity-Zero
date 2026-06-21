"""Shared HTTP session and connection pooling.

Provides process-wide singleton httpx.AsyncClient and requests.Session instances
with configurable connection pools. Avoids creating new clients per request.

Usage:
    from src.core.utils.shared_sessions import (
        get_shared_async_client,
        get_shared_sync_session,
        get_shared_boto3_client,
    )

    client = get_shared_async_client()
    session = get_shared_sync_session()
    s3 = get_shared_boto3_client("s3", region_name="us-east-1")
"""

from __future__ import annotations

import atexit
import logging
import threading
from typing import Any

import httpx
import requests

logger = logging.getLogger(__name__)

# --- Async httpx client (singleton) ---

_async_client: httpx.AsyncClient | None = None
_async_client_lock = threading.Lock()


def get_shared_async_client(
    verify_ssl: bool = True,
    follow_redirects: bool = True,
    timeout: float = 30.0,
    max_connections: int = 100,
    max_keepalive: int = 20,
) -> httpx.AsyncClient:
    """Return a process-wide shared httpx.AsyncClient.

    Configures connection pooling with limits to prevent fd exhaustion.
    Subsequent calls return the same client instance (ignoring params).
    """
    global _async_client
    if _async_client is not None and not _async_client.is_closed:
        return _async_client

    with _async_client_lock:
        if _async_client is not None and not _async_client.is_closed:
            return _async_client

        _async_client = httpx.AsyncClient(
            verify=verify_ssl,
            follow_redirects=follow_redirects,
            timeout=timeout,
            limits=httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max_keepalive,
                keepalive_expiry=30.0,
            ),
        )
        logger.debug("Created shared httpx.AsyncClient (max_conn=%d)", max_connections)
        return _async_client


# --- Sync requests.Session (thread-local singleton) ---

_thread_local = threading.local()


def get_shared_sync_session() -> requests.Session:
    """Return a thread-local shared requests.Session.

    Each thread gets its own session to avoid thread-safety issues,
    but sessions are reused within a thread.
    """
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        _thread_local.session = session
    return session


# --- Shared boto3 sessions/clients ---

_boto3_sessions: dict[str, Any] = {}
_boto3_clients: dict[tuple[str, str | None], Any] = {}
_boto3_lock = threading.Lock()


def get_shared_boto3_client(
    service_name: str,
    region_name: str | None = None,
    endpoint_url: str | None = None,
) -> Any:
    """Return a shared boto3 client for the given service.

    Clients are cached by (service_name, region_name) to avoid creating
    new HTTP connections for each request.
    """
    if not _boto3_available():
        raise ImportError("boto3 is required. Install with: pip install boto3")

    import boto3

    cache_key = (service_name, region_name)
    if cache_key in _boto3_clients:
        return _boto3_clients[cache_key]

    with _boto3_lock:
        if cache_key in _boto3_clients:
            return _boto3_clients[cache_key]

        kwargs: dict[str, Any] = {}
        if region_name:
            kwargs["region_name"] = region_name
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url

        client = boto3.client(service_name, **kwargs)
        _boto3_clients[cache_key] = client
        logger.debug("Created shared boto3 client for %s (region=%s)", service_name, region_name)
        return client


def _boto3_available() -> bool:
    try:
        import boto3  # noqa: F401

        return True
    except ImportError:
        return False


def _cleanup_shared_sessions() -> None:
    """Clean up shared sessions at process exit."""
    global _async_client
    with _async_client_lock:
        if _async_client is not None:
            try:
                if not _async_client.is_closed:
                    try:
                        loop = __import__("asyncio").get_event_loop()
                        if not loop.is_closed():
                            loop.run_until_complete(_async_client.aclose())
                    except RuntimeError:
                        pass
            except Exception:
                pass
            _async_client = None

    for session in getattr(_thread_local, "_sessions", []):
        try:
            session.close()
        except Exception:
            pass


atexit.register(_cleanup_shared_sessions)


__all__ = [
    "get_shared_async_client",
    "get_shared_sync_session",
    "get_shared_boto3_client",
]
