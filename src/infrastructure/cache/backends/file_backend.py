"""Backwards-compatible re-export shim for the renamed file backend.

All new code should import from ``backends.file``::

    from src.infrastructure.cache.backends.file import FileBackend

"""

from src.infrastructure.cache.backends.file import FileBackend

__all__ = ["FileBackend"]
