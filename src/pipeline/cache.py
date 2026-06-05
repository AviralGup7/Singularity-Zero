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

from src.core.logging.trace_logging import get_pipeline_logger
from src.pipeline.storage import ensure_dir

logger = get_pipeline_logger(__name__)


class TTLMode(StrEnum):
    """TTL enforcement strategy for cached responses."""

    HARD_TTL = "hard_ttl"
    STALE_WHILE_REVALIDATE = "stale_while_revalidate"


def cache_enabled(settings: dict[str, Any]) -> bool:
    return bool(settings.get("enabled", True))


def _read_cached_payload(path: Path) -> Any | None:
    """Read a cached payload from file, supporting gzip fallback and decoding.

    Args:
        path: Path to the cached file.

    Returns:
        Decoded JSON payload, or None if missing or corrupt.
    """
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
    """Load a cached set from a JSON file.

    Args:
        path: Path to the cached JSON file.

    Returns:
        Set of strings, or empty set if file is missing or corrupt.
    """
    payload = _read_cached_payload(path)
    if not isinstance(payload, list):
        return set()
    return {str(item).strip() for item in payload if str(item).strip()}


def save_cached_set(path: Path, items: set[str], *, compress: bool = True) -> None:
    """Save a set to a JSON file with optional gzip compression.

    Args:
        path: Path to the cached JSON file.
        items: Set of strings to save.
        compress: Whether to use gzip compression (default True).
    """
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
    """Load a cached JSON file, returning an empty dict if missing or corrupt.

    Args:
        path: Path to the cached JSON file.

    Returns:
        Parsed dict, or empty dict if file is missing, corrupt, or not a dict.
    """
    payload = _read_cached_payload(path)
    return payload if isinstance(payload, dict) else {}


def save_cached_json(path: Path, payload: dict[str, Any], *, compress: bool = True) -> None:
    """Save a dict to a JSON file with optional gzip compression.

    Args:
        path: Path to the cached JSON file.
        payload: Dict to save as JSON.
        compress: Whether to use gzip compression (default True).
    """
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
