"""Cache utilities for persisting and loading pipeline data between runs.

Provides caching for sets, JSON objects, and HTTP response records with
TTL-based freshness checking and gzip compression support.
"""

import gzip
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from src.pipeline.storage import ensure_dir

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


def cache_enabled(settings: dict[str, Any]) -> bool:
    return bool(settings.get("enabled", True))


def load_cached_set(path: Path) -> set[str]:
    """Load a cached set from a JSON file.

    Args:
        path: Path to the cached JSON file.

    Returns:
        Set of strings, or empty set if file is missing or corrupt.
    """
    if not path.exists():
        if path.suffix != ".gz":
            gz_path = path.with_suffix(path.suffix + ".gz")
            if gz_path.exists():
                path = gz_path
            else:
                return set()
        else:
            return set()

    try:
        if path.suffix == ".gz":
            data = gzip.decompress(path.read_bytes())
            payload = json.loads(data.decode("utf-8"))
        else:
            payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read cache file (%s): %s", exc.__class__.__name__, path)
        return set()
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
    if compress:
        path = path.with_suffix(path.suffix + ".gz")
        data = gzip.compress(data, compresslevel=6)
    _atomic_write(path, data)


def load_cached_json(path: Path) -> dict[str, Any]:
    """Load a cached JSON file, returning an empty dict if missing or corrupt.

    Args:
        path: Path to the cached JSON file.

    Returns:
        Parsed dict, or empty dict if file is missing, corrupt, or not a dict.
    """
    if not path.exists():
        if path.suffix != ".gz":
            gz_path = path.with_suffix(path.suffix + ".gz")
            if gz_path.exists():
                path = gz_path
            else:
                return {}
        else:
            return {}

    try:
        if path.suffix == ".gz":
            data = gzip.decompress(path.read_bytes())
            payload = json.loads(data.decode("utf-8"))
        else:
            payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read cache file (%s): %s", exc.__class__.__name__, path)
        return {}
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
    if compress:
        path = path.with_suffix(path.suffix + ".gz")
        data = gzip.compress(data, compresslevel=6)
    _atomic_write(path, data)


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


def response_cache_fresh(
    record: dict[str, Any], ttl_hours: int, content_hash: str | None = None
) -> bool:
    """Check if a cached response is still fresh based on TTL and optional content hash.

    Args:
        record: Cached response record with 'cached_at_epoch' and optional 'content_hash'.
        ttl_hours: Time-to-live in hours.
        content_hash: Optional content hash for validation.

    Returns:
        True if cache is fresh, False otherwise.
    """
    if ttl_hours <= 0:
        return False
    fetched_at = float(record.get("cached_at_epoch", 0))
    if fetched_at <= 0:
        return False
    if content_hash and record.get("content_hash") != content_hash:
        return False
    return (time.time() - fetched_at) < ttl_hours * 3600
