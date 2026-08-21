"""Threat-intelligence facade. Scoring stays in analysis; FP loop in learning."""

from src.intel.feeds import (
    FeedDescriptor,
    configured_feed_keys,
    is_feed_configured,
    list_feeds,
)

__all__ = [
    "FeedDescriptor",
    "configured_feed_keys",
    "is_feed_configured",
    "list_feeds",
]
