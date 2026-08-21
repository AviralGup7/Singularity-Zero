"""Unified cache facade. Pipeline and dashboard are clients."""

from __future__ import annotations

from typing import Any


def get_cache() -> Any:
    from src.pipeline.unified_cache import get_unified_cache

    return get_unified_cache()


__all__ = ["get_cache"]
