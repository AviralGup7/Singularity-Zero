"""Cache utilities for persisting and loading pipeline data between runs.

Provides caching for sets, JSON objects, and HTTP response records with
TTL-based freshness checking and gzip compression support.
"""

import gzip
import json
import os
import tempfile
import time
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Any

from src.pipeline.unified_cache import (
    CacheKeyNormalizer,
    cache_enabled,
    _unified_cache as _unified,
    load_cached_json,
    load_cached_set,
    save_cached_json,
    save_cached_set,
)


class TTLMode(StrEnum):
    """TTL enforcement strategy for cached responses."""

    HARD_TTL = "hard_ttl"
    STALE_WHILE_REVALIDATE = "stale_while_revalidate"


def cache_enabled(settings: dict[str, Any]) -> bool:
    return bool(settings.get("enabled", True))


_unified = UnifiedCache()


def _read_cached_payload(path: Path) -> Any | None:
    value = load_cached_json(path)
    return value if value else None


def load_cached_set(path: Path) -> set[str]:
    return load_cached_set(path)


def save_cached_set(path: Path, items: set[str], *, compress: bool = True) -> None:
    save_cached_set(path, items)


def load_cached_json(path: Path) -> dict[str, Any]:
    return load_cached_json(path)


def save_cached_json(path: Path, payload: dict[str, Any], *, compress: bool = True) -> None:
    save_cached_json(path, payload)


def _atomic_write(path: Path, data: bytes) -> None:
    """Write data to a file atomically using a temp file and rename.

    This prevents corruption if the process crashes mid-write.

    Args:
        path: Target file path.
        data: Bytes to write.
    """
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
        # Fix Audit #88: Log atomic write failure
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
    """Check if a cached response is still fresh based on TTL and optional content hash.

    Supports both HARD_TTL (current behavior) and STALE_WHILE_REVALIDATE mode.
    In STALE_WHILE_REVALIDATE mode, returns True for stale-but-recent entries
    and triggers background refresh via ``background_callback`` if provided.

    Args:
        record: Cached response record with 'cached_at_epoch' and optional 'content_hash'.
        ttl_hours: Time-to-live in hours.
        content_hash: Optional content hash for validation.
        ttl_mode: TTL enforcement strategy (HARD_TTL or STALE_WHILE_REVALIDATE).
        background_callback: Optional callable invoked with the stale record
            to trigger an async refresh.

    Returns:
        True if cache is fresh (or stale-but-reusable under STALE_WHILE_REVALIDATE).
    """
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
