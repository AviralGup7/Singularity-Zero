"""Backwards-compatible re-export shim for the renamed Redis backend.

All new code should import from ``backends.redis``::

    from src.infrastructure.cache.backends.redis import RedisBackend

"""

from src.infrastructure.cache.backends.redis import RedisBackend

__all__ = ["RedisBackend"]
