"""Cache key normalization, TTL freshness checks, and helper utilities."""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from src.pipeline.unified_cache.models import CachePriority, NamespaceRouting


class CacheKeyNormalizer:
    """Normalize cache keys to enforce canonical form.

    Applied rules (in order):
    1. Strip trailing slashes.
    2. Lowercase the entire key.
    3. Normalize scheme: ``http://`` → ``https://``.
    4. Normalize ``www.`` prefix: ``www.example.com`` → ``example.com``.
    """

    @staticmethod
    def normalize(key: str) -> str:
        key = key.rstrip("/")
        key = key.lower()
        if key.startswith("http://"):
            key = "https://" + key[7:]
        if key.startswith("https://www."):
            key = "https://" + key[12:]
        return key

    @staticmethod
    def path_to_key(path: Path) -> str:
        normalized = str(path).replace("\\", "/").rstrip("/").lower()
        return f"legacy_path:{normalized}"


def _hash_key(key: str) -> str:
    """Return a stable 64-hex SHA-256 of ``key`` for filesystem paths."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Atomically write ``data`` to ``path`` using a tempfile in the same dir."""
    import logging
    logger = logging.getLogger(__name__)

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.chmod(tmp_path, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp_path, str(path))
        tmp_path = ""
    except Exception:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError as exc:
                logger.warning("Operation failed in unified_cache: %s", exc, exc_info=True)
        raise


def _parse_namespace(key: str) -> str:
    return key.split(":", 1)[0] if ":" in key else key


def _resolve_routing(namespace: str, strict: bool = False) -> NamespaceRouting:
    from src.pipeline.unified_cache.models import _NAMESPACE_ROUTING, Backend
    if namespace in _NAMESPACE_ROUTING:
        return _NAMESPACE_ROUTING[namespace]
    return NamespaceRouting(default_backend=Backend.SQLITE, default_priority=CachePriority.NORMAL)


def response_cache_fresh(
    record: dict[str, Any],
    ttl_hours: int,
    content_hash: str | None = None,
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
    return (time.time() - fetched_at) < ttl_hours * 3600
