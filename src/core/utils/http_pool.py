"""Connection pooling for HTTP requests using urllib3.

Provides a thread-safe singleton PoolManager with configurable
connection pooling, retries, and keep-alive timeouts.
"""

import threading

import urllib3

_DEFAULT_POOL_CONNECTIONS = 10
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BLOCK = True
_DEFAULT_TIMEOUT = 10.0

_pool_manager: urllib3.PoolManager | None = None
_pool_lock = threading.Lock()


def get_pooled_connection(
    pool_connections: int = _DEFAULT_POOL_CONNECTIONS,
    max_retries: int = _DEFAULT_MAX_RETRIES,
    block: bool = _DEFAULT_BLOCK,
    timeout: float = _DEFAULT_TIMEOUT,
) -> urllib3.PoolManager:
    """Return a thread-safe shared urllib3.PoolManager instance.

    Args:
        pool_connections: Maximum number of connections to keep in the pool.
        max_retries: Number of retries per request.
        block: Whether to block when the pool is exhausted.
        timeout: Default timeout in seconds for requests.

    Returns:
        A configured urllib3.PoolManager instance.
    """
    global _pool_manager

    if _pool_manager is not None:
        return _pool_manager

    with _pool_lock:
        if _pool_manager is not None:
            return _pool_manager

        retry = urllib3.util.Retry(
            total=max_retries,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )

        timeout_config = urllib3.util.Timeout(
            connect=timeout,
            read=timeout,
        )

        _pool_manager = urllib3.PoolManager(
            num_pools=pool_connections,
            maxsize=pool_connections,
            block=block,
            retries=retry,
            timeout=timeout_config,
        )

    return _pool_manager


def reset_pool() -> None:
    """Reset the global connection pool. Useful for testing."""
    global _pool_manager
    with _pool_lock:
        if _pool_manager is not None:
            _pool_manager.clear()
            _pool_manager = None
