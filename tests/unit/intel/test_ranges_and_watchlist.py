from __future__ import annotations

from src.intel.ioc import classify_indicator, extract_indicators
from src.intel.ranges import group_by_kind, in_cidr, private_indicator, routable
from src.intel.watchlist import Watchlist


def test_cidr_and_private() -> None:
    assert in_cidr("10.1.2.3", "10.0.0.0/8")
    assert not in_cidr("8.8.8.8", "10.0.0.0/8")
    assert private_indicator("10.0.0.5")
    assert routable("1.1.1.1")
    grouped = group_by_kind(extract_indicators("1.1.1.1 evil.test CVE-2020-1234"))
    assert "ipv4" in grouped


def test_watchlist_match() -> None:
    watch = Watchlist()
    watch.add("evil.test")
    hits = watch.matching("request to evil.test/login")
    assert hits
    assert classify_indicator(hits[0].value).value == "evil.test"
