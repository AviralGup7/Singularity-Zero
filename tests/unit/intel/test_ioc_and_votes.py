from __future__ import annotations

from src.intel import (
    FeedAggregator,
    FeedVote,
    IndicatorKind,
    Verdict,
    Watchlist,
    classify_indicator,
    combine_votes,
    correlate_finding,
    extract_indicators,
)


def test_classify_and_extract() -> None:
    assert classify_indicator("1.1.1.1").kind is IndicatorKind.IPV4
    assert classify_indicator("CVE-2024-1234").kind is IndicatorKind.CVE
    found = extract_indicators("hit 8.8.8.8 and evil.example.com CVE-2021-44228")
    kinds = {item.kind for item in found}
    assert IndicatorKind.IPV4 in kinds
    assert IndicatorKind.DOMAIN in kinds
    assert IndicatorKind.CVE in kinds


def test_aggregator_and_correlation() -> None:
    agg = FeedAggregator()
    agg.seed("evil.example.com", FeedVote(source="vt", verdict=Verdict.MALICIOUS, score=0.9))
    result = agg.lookup("evil.example.com")
    assert result.verdict is Verdict.MALICIOUS
    intel = correlate_finding({"id": "f1", "url": "https://evil.example.com/x"}, agg)
    assert intel.verdict is Verdict.MALICIOUS
    assert combine_votes([]) is Verdict.UNKNOWN


def test_watchlist() -> None:
    watch = Watchlist()
    watch.add("10.0.0.1")
    assert watch.contains("10.0.0.1")
    assert watch.matching("talked to 10.0.0.1 from app")
