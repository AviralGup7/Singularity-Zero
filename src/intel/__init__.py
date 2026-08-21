"""Threat-intelligence facade."""

from src.intel.aggregator import FeedAggregator, LookupResult
from src.intel.correlation import FindingIntel, correlate_finding, correlate_findings
from src.intel.feeds import (
    FeedDescriptor,
    configured_feed_keys,
    is_feed_configured,
    list_feeds,
)
from src.intel.ioc import Indicator, IndicatorKind, classify_indicator, extract_indicators
from src.intel.verdict import FeedVote, Verdict, combine_votes
from src.intel.watchlist import Watchlist

__all__ = [
    "FeedAggregator",
    "FeedDescriptor",
    "FeedVote",
    "FindingIntel",
    "Indicator",
    "IndicatorKind",
    "LookupResult",
    "Verdict",
    "Watchlist",
    "classify_indicator",
    "combine_votes",
    "configured_feed_keys",
    "correlate_finding",
    "correlate_findings",
    "extract_indicators",
    "is_feed_configured",
    "list_feeds",
]
