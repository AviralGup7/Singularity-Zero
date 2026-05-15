"""Protocol and shared helpers for cache backends.

This module defines the CacheBackend protocol that all backends
must conform to and shared thread-local connection utilities.
"""

import sqlite3
import threading
from typing import Any, Protocol


class CacheBackend(Protocol):
    """Protocol defining the interface for all cache backends.

    All backend implementations must provide these methods.
    The Protocol class enables structural subtyping for duck-typed backends.
    """

    def get(self, key: str) -> Any | None: ...
    def set(self, key: str, value: Any, ttl: int | None = None) -> None: ...
    def delete(self, key: str) -> bool: ...
    def exists(self, key: str) -> bool: ...
    def clear(self) -> int: ...
    def size(self) -> int: ...
    def cleanup_expired(self) -> int: ...
    def get_stats(self) -> dict[str, Any]: ...
    def close(self) -> None: ...


class _ThreadLocalConnections(threading.local):
    """Thread-local storage for SQLite connections."""

    def __init__(self) -> None:
        self.conn: sqlite3.Connection | None = None
