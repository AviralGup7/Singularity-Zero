"""Collect votes from configured feeds without requiring API keys in tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.intel.feeds import configured_feed_keys, is_feed_configured
from src.intel.ioc import Indicator, classify_indicator, related_indicators
from src.intel.verdict import FeedVote, Verdict, combine_votes, parse_verdict


@dataclass
class LookupResult:
    indicator: Indicator
    votes: list[FeedVote] = field(default_factory=list)
    configured: tuple[str, ...] = ()

    @property
    def verdict(self) -> Verdict:
        return combine_votes(self.votes)

    def to_dict(self) -> dict[str, object]:
        return {
            "indicator": {"kind": self.indicator.kind.value, "value": self.indicator.normalized()},
            "verdict": self.verdict.value,
            "configured": list(self.configured),
            "votes": [
                {
                    "source": vote.source,
                    "verdict": vote.verdict.value,
                    "score": vote.score,
                    "tags": list(vote.tags),
                }
                for vote in self.votes
            ],
        }


class FeedAggregator:
    """Offline-capable aggregator. Live HTTP clients stay in intelligence.feeds."""

    def __init__(self) -> None:
        self._manual: dict[str, list[FeedVote]] = {}

    def seed(self, indicator: Indicator | str, vote: FeedVote) -> None:
        key = classify_indicator(indicator if isinstance(indicator, str) else indicator.value)
        bucket = self._manual.setdefault(f"{key.kind}:{key.normalized()}", [])
        bucket.append(vote)

    def lookup(self, raw: object) -> LookupResult:
        indicator = classify_indicator(raw) if not isinstance(raw, Indicator) else raw
        votes: list[FeedVote] = []
        seen: set[tuple[str, str]] = set()
        for item in related_indicators(indicator):
            key = f"{item.kind}:{item.normalized()}"
            for vote in self._manual.get(key, []):
                identity = (vote.source, vote.verdict.value)
                if identity in seen:
                    continue
                seen.add(identity)
                votes.append(vote)
        return LookupResult(indicator=indicator, votes=votes, configured=configured_feed_keys())

    def lookup_many(self, values: list[object]) -> list[LookupResult]:
        return [self.lookup(value) for value in values]

    def seed_from_mapping(self, payload: dict[str, Any]) -> None:
        source = str(payload.get("source") or "manual")
        verdict = parse_verdict(payload.get("verdict"))
        score_raw = payload.get("score") or 0.0
        score = float(score_raw) if isinstance(score_raw, (int, float, str)) else 0.0
        tags_raw = payload.get("tags") or []
        tags = (
            tuple(str(tag) for tag in tags_raw if tag)
            if isinstance(tags_raw, (list, tuple))
            else ()
        )
        value = payload.get("value") or payload.get("indicator")
        self.seed(str(value), FeedVote(source=source, verdict=verdict, score=score, tags=tags))


def unavailable_feeds() -> tuple[str, ...]:
    return tuple(
        key for key in ("virustotal", "otx", "misp", "shodan") if not is_feed_configured(key)
    )
