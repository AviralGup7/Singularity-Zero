"""Backward-compatible re-export of the lifecycle manager.

The canonical implementation has moved to src.core.lifecycle.
This module re-exports the public API so existing import paths continue
to work during the migration period.
"""

from src.core.lifecycle import LifecycleManager, get_lifecycle_manager

__all__ = [
    "LifecycleManager",
    "get_lifecycle_manager",
]
