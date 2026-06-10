"""Cache utilities for persisting and loading pipeline data between runs.

Provides caching for sets, JSON objects, and HTTP response records with
TTL-based freshness checking.
"""

import gzip
import io
import json
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

# Maximum uncompressed size for cached gzip payloads (64 MiB).
_MAX_DECOMPRESSED_BYTES: int = 64 * 1024 * 1024

from src.core.logging.trace_logging import get_pipeline_logger
from src.pipeline.unified_cache import (
    Backend,
    CachePriority,
    TTLMode,
    cache_enabled,
)

logger = get_pipeline_logger(__name__)

__all__ = [
    "TTLMode",
    "Backend",
    "CachePriority",
    "response_cache_fresh",
    "cache_enabled",
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
            raw = resolved_path.read_bytes()
            decompressor = gzip.GzipFile(fileobj=io.BytesIO(raw))
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = decompressor.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_DECOMPRESSED_BYTES:
                    raise ValueError(f"Gzip payload exceeds {_MAX_DECOMPRESSED_BYTES} byte limit")
                chunks.append(chunk)
            data = b"".join(chunks)
            return json.loads(data.decode("utf-8"))
        else:
            return json.loads(resolved_path.read_text(encoding="utf-8"))
    except (EOFError, UnicodeDecodeError, json.JSONDecodeError, OSError, ValueError) as exc:
        logger.warning("Failed to read cache file (%s): %s", exc.__class__.__name__, resolved_path)
        return None


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
            except OSError as exc:
                logger.warning("Operation failed in cache.py: %s", exc, exc_info=True)  # noqa: BLE001
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError as exc:
                logger.warning("Operation failed in cache.py: %s", exc, exc_info=True)  # noqa: BLE001
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
