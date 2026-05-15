"""Cache backend package.

Each module in this package implements the CacheBackend protocol
defined in ``protocol.py``.  Import from this package to get
all backends in one place::

    from src.infrastructure.cache.backends import (
        SQLiteBackend,
        RedisBackend,
        FileBackend,
        MemoryBackend,
        CacheBackend,
    )
"""

from src.infrastructure.cache.backends.file_backend import FileBackend
from src.infrastructure.cache.backends.memory import MemoryBackend
from src.infrastructure.cache.backends.protocol import CacheBackend
from src.infrastructure.cache.backends.redis_backend import RedisBackend
from src.infrastructure.cache.backends.sqlite import SQLiteBackend

__all__ = ["CacheBackend", "SQLiteBackend", "RedisBackend", "FileBackend", "MemoryBackend"]
