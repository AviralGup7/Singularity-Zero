"""Backwards-compatible re-export shim for the renamed warmer module.

These functions have moved to ``src.infrastructure.cache.warming``::

    from src.infrastructure.cache.warming import warm_from_json, warm_from_sqlite, warm_from_directory

"""

from src.infrastructure.cache.warming import (
    warm_from_directory,
    warm_from_json,
    warm_from_sqlite,
)

__all__ = ["warm_from_directory", "warm_from_json", "warm_from_sqlite"]
