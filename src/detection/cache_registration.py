"""Detection cache registration implementation.

This module implements the DetectionCacheInvalidator protocol and registers
itself with core.plugins at import time.
"""

from __future__ import annotations

import logging

from src.core.plugins.registration_hooks import register_detection_cache_invalidator

logger = logging.getLogger(__name__)


class DetectionCacheInvalidatorImpl:
    """Implementation of the DetectionCacheInvalidator protocol."""

    def invalidate_detection_cache(self) -> None:
        """Invalidate the detection plugin cache."""
        try:
            from src.detection import registry

            registry._DETECTION_PLUGIN_OPTIONS = None
        except Exception as exc:
            logger.debug("Unable to invalidate detection plugin cache: %s", exc)


def register_detection_hooks() -> None:
    """Register the detection cache hooks with core."""
    invalidator = DetectionCacheInvalidatorImpl()
    register_detection_cache_invalidator(invalidator)
    logger.debug("Detection cache hooks registered")


# Auto-register when imported
register_detection_hooks()
