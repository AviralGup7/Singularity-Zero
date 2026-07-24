"""Unified cache facade routing structured data to SQLite and blobs to disk.

Provides a single key space over the legacy ``PersistentCache`` (SQLite WAL)
and on-disk JSON / blob storage. Eliminates the coherence gap between
``src.pipeline.cache`` and ``src.pipeline.cache_backend`` by recording every
write in a routing index so the facade always knows which backend holds the
bytes for a given key.

Backward-compatible re-exports: all public symbols from the original
monolithic ``unified_cache.py`` module are re-exported here so that
existing ``from src.pipeline.unified_cache import ...`` statements
continue to work unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from src.pipeline.unified_cache.coalescing import CoalescingCacheWrapper
from src.pipeline.unified_cache.models import (
    _DATA_PREFIX,
    _ROUTING_PREFIX,
    DATA_PREFIX,
    NAMESPACE_ROUTING,
    PRIORITY_RANK,
    ROUTING_PREFIX,
    Backend,
    CachePriority,
    NamespaceRouting,
    TTLMode,
)
from src.pipeline.unified_cache.policies import (
    CacheKeyNormalizer,
    _atomic_write_bytes,
    _hash_key,
    _parse_namespace,
    _resolve_routing,
    response_cache_fresh,
)
from src.pipeline.unified_cache.storage import UnifiedCache

__all__ = [
    "Backend",
    "CacheKeyNormalizer",
    "CachePriority",
    "CoalescingCacheWrapper",
    "DATA_PREFIX",
    "NAMESPACE_ROUTING",
    "PRIORITY_RANK",
    "ROUTING_PREFIX",
    "TTLMode",
    "UnifiedCache",
    "_atomic_write_bytes",
    "_data_prefix",
    "_hash_key",
    "_parse_namespace",
    "_resolve_routing",
    "_routing_prefix",
    "_unified_cache",
    "cache_enabled",
    "get_unified_cache",
    "load_cached_json",
    "load_cached_set",
    "response_cache_fresh",
    "save_cached_json",
    "save_cached_set",
]

_data_prefix = _DATA_PREFIX
_routing_prefix = _ROUTING_PREFIX


_unified_cache = UnifiedCache()


def get_unified_cache() -> UnifiedCache:
    """Return the process-wide UnifiedCache singleton."""
    return _unified_cache


def cache_enabled(settings: Any) -> bool:
    if isinstance(settings, dict):
        return bool(settings.get("enabled", True))
    if hasattr(settings, "enabled"):
        return bool(getattr(settings, "enabled", True))
    return True


def load_cached_json(path: Path) -> dict[str, Any] | None:
    try:
        raw = path.read_bytes()
        return dict(json.loads(raw.decode("utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def save_cached_json(
    path: Path, payload: dict[str, Any] | list[Any], *, compress: bool = True
) -> None:
    data = json.dumps(payload).encode("utf-8")
    _atomic_write_bytes(path, data)


def load_cached_set(path: Path) -> set[str]:
    loaded = load_cached_json(path)
    return set(loaded) if isinstance(loaded, list) else set()


def save_cached_set(path: Path, items: Iterable[str], *, compress: bool = True) -> None:
    save_cached_json(path, list(items), compress=compress)


def reset_unified_cache() -> None:
    """Reset the unified cache singleton.

    Closes the current cache instance (if any) and resets the
    class-level singleton pointer so the next call to
    :func:`get_unified_cache` creates a fresh instance.
    """
    global _unified_cache
    if _unified_cache is not None:
        try:
            _unified_cache.close()
        except Exception:
            pass
        _unified_cache = None
    UnifiedCache._instance = None
