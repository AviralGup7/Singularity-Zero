"""Intel aggregator stats."""

from __future__ import annotations

from src.intel.aggregator import FeedAggregator, LookupResult
from src.intel.verdict import Verdict


def lookup_stats(results: list[LookupResult]) -> dict[str, int]:
    return {
        "total": len(results),
        "malicious": sum(1 for item in results if item.verdict is Verdict.MALICIOUS),
        "suspicious": sum(1 for item in results if item.verdict is Verdict.SUSPICIOUS),
        "harmless": sum(1 for item in results if item.verdict is Verdict.HARMLESS),
        "unknown": sum(1 for item in results if item.verdict is Verdict.UNKNOWN),
        "configured_feeds": len(results[0].configured) if results else 0,
    }


def aggregator_size(aggregator: FeedAggregator) -> int:
    return len(aggregator._manual)  # noqa: SLF001
