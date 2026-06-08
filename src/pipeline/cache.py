"""Cache utilities for persisting and loading pipeline data between runs.

Provides caching for sets, JSON objects, and HTTP response records with
TTL-based freshness checking.
"""

import gzip
import json
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.pipeline.unified_cache import (
    CacheKeyNormalizer,
    TTLMode,
    Backend,
    CachePriority,
    cache_enabled,
    _unified_cache as _unified,
    UnifiedCache,
    load_cached_json,
    load_cached_set,
    save_cached_json,
    save_cached_set,
)

logger = get_pipeline_logger(__name__)

__all__ = [
    "TTLMode",
    "Backend",
    "CachePriority",
    "response_cache_fresh",
    "cache_enabled",
    "load_cached_json",
    "load_cached_set",
    "save_cached_json",
    "save_cached_set",
]


def _read_cached_payload(path: Path) -> Any | None:
    """Read a cached payload from file, supporting gzip fallback and decoding."""
    if path.name.endswith(".gz"):
        gz_path = path
        normal_path = path.parent / path.name[:-3]
    else:
        normal_path = path
        gz_path = path.parent / (path.name + ".gz")

    resolved_path = None
    if normal_path.exists():
        resolved_path = normal_path
    elif gz_path.exists():
        resolved_path = gz_path
    else:
        return None

    try:
        if resolved_path.name.endswith(".gz"):
            data = gzip.decompress(resolved_path.read_bytes())
            return json.loads(data.decode("utf-8"))
        else:
            return json.loads(resolved_path.read_text(encoding="utf-8"))
    except (EOFError, UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read cache file (%s): %s", exc.__class__.__name__, resolved_path)
        return None


def load_cached_set(path: Path) -> set[str]:
    """Load a cached set from a JSON file."""
    payload = _read_cached_payload(path)
    if not isinstance(payload, list):
        return set()
    return {str(item).strip() for item in payload if str(item).strip()}


def save_cached_set(path: Path, items: set[str], *, compress: bool = True) -> None:
    """Save a set to a JSON file with optional gzip compression."""
    from src.pipeline.storage import ensure_dir
    ensure_dir(path.parent)
    data = json.dumps(sorted(items)).encode("utf-8")
    if path.name.endswith(".gz"):
        base_path = path.parent / path.name[:-3]
        gz_path = path
    else:
        base_path = path
        gz_path = path.parent / (path.name + ".gz")

    if compress:
        data = gzip.compress(data, compresslevel=6)
        _atomic_write(gz_path, data)
        _remove_stale_alternate(base_path)
    else:
        _atomic_write(base_path, data)
        _remove_stale_alternate(gz_path)


def load_cached_json(path: Path) -> dict[str, Any]:
    """Load a cached JSON file."""
    payload = _read_cached_payload(path)
    return payload if isinstance(payload, dict) else {}


def save_cached_json(path: Path, payload: dict[str, Any], *, compress: bool = True) -> None:
    """Save a dict to a JSON file with optional gzip compression."""
    from src.pipeline.storage import ensure_dir
    ensure_dir(path.parent)
    data = json.dumps(payload).encode("utf-8")
    if path.name.endswith(".gz"):
        base_path = path.parent / path.name[:-3]
        gz_path = path
    else:
        base_path = path
        gz_path = path.parent / (path.name + ".gz")

    if compress:
        data = gzip.compress(data, compresslevel=6)
        _atomic_write(gz_path, data)
        _remove_stale_alternate(base_path)
    else:
        _atomic_write(base_path, data)
        _remove_stale_alternate(gz_path)


def _atomic_write(path: Path, data: bytes) -> None:
    """Write data to a file atomically using a temp file and rename."""
    parent = path.parent
    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=str(parent), suffix=".tmp")
        os.chmod(tmp_path, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            fd = None
        os.replace(tmp_path, path)
        tmp_path = None
    except Exception as exc:
        logger.error("Atomic write failed for %s: %s", path, exc)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise


def _remove_stale_alternate(path: Path) -> None:
    """Remove an older cache representation after its replacement is durable."""
    try:
        if path.exists():
            path.unlink()
    except OSError as exc:
        logger.warning("Failed to remove stale cache file %s: %s", path, exc)


def response_cache_fresh(
    record: dict[str, Any],
    ttl_hours: int,
    content_hash: str | None = None,
    *,
    ttl_mode: TTLMode = TTLMode.HARD_TTL,
    stale_threshold_hours: int | None = None,
    background_callback: Callable[[dict[str, Any]], None] | None = None,
) -> bool:
    if ttl_hours <= 0:
        return False
    try:
        fetched_at = float(record.get("cached_at_epoch", 0))
    except (TypeError, ValueError):
        return False
    if fetched_at <= 0:
        return False
    if content_hash and record.get("content_hash") != content_hash:
        return False
    age_seconds = time.time() - fetched_at
    max_age_seconds = ttl_hours * 3600
    if age_seconds < max_age_seconds:
        return True
    if ttl_mode == TTLMode.STALE_WHILE_REVALIDATE and background_callback is not None:
        background_callback(record)
    return False
