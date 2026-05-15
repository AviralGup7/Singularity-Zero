"""Backwards-compatible re-exports for the cache backends package.

This module is now a thin wrapper that delegates to the new
``src.infrastructure.cache.backends`` package.  All backend
implementations have been split into focused modules:

- ``backends/protocol.py`` — CacheBackend protocol
- ``backends/sqlite.py``    — SQLiteBackend
- ``backends/redis_backend.py`` — RedisBackend
- ``backends/file_backend.py`` — FileBackend
- ``backends/memory.py``    — MemoryBackend

New code should import directly from the package::

    from src.infrastructure.cache.backends import SQLiteBackend

"""

from src.infrastructure.cache.backends import (
    CacheBackend,
    FileBackend,
    MemoryBackend,
    RedisBackend,
    SQLiteBackend,
)

__all__ = [
    "CacheBackend",
    "FileBackend",
    "MemoryBackend",
    "RedisBackend",
    "SQLiteBackend",
]
