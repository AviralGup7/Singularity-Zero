"""Coverage for previously untested web-cache-poison helper functions."""

from __future__ import annotations

import pytest

from src.exploitation.web_cache_poison import (
    CACHE_HEADERS,
    WCP_HEADERS,
    WCP_PAYLOADS,
    _add_cache_bust,
    _check_reflection,
    has_cache_header,
)


class _Resp:
    def __init__(self, headers: dict[str, str], text: str = "") -> None:
        self.headers = headers
        self.text = text


@pytest.mark.unit
def test_has_cache_header_finds_known_indicators() -> None:
    found = has_cache_header(_Resp({"X-Cache": "HIT", "CF-Cache-Status": "MISS", "Date": "now"}))
    assert "x-cache" in found
    assert "cf-cache-status" in found
    assert "date" not in found


@pytest.mark.unit
def test_has_cache_header_empty_when_no_cache_layer() -> None:
    assert has_cache_header(_Resp({"content-type": "text/html"})) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("url", "buster", "expected"),
    [
        ("https://a.test/x", "cb1", "https://a.test/x?_cachebust=cb1"),
        ("https://a.test/x?q=1", "cb2", "https://a.test/x?q=1&_cachebust=cb2"),
        ("https://a.test/x#frag", "cb3", "https://a.test/x?_cachebust=cb3#frag"),
        ("https://a.test/x?q=1#f", "cb4", "https://a.test/x?q=1&_cachebust=cb4#f"),
    ],
)
def test_add_cache_bust_preserves_query_and_fragment(url: str, buster: str, expected: str) -> None:
    assert _add_cache_bust(url, buster) == expected


@pytest.mark.unit
def test_check_reflection_in_header_and_body() -> None:
    reflected, locations = _check_reflection(
        _Resp({"X-Forwarded-Host": "ToXiCaChe"}, "hello toxicache world"),
        "toxicache",
    )
    assert reflected is True
    assert "X-Forwarded-Host" in locations
    assert "body" in locations


@pytest.mark.unit
def test_check_reflection_header_name_and_miss() -> None:
    hit, locations = _check_reflection(_Resp({"X-toxicache-Debug": "1"}, "ok"), "toxicache")
    assert hit is True
    assert "X-toxicache-Debug" in locations
    miss, empty = _check_reflection(_Resp({"Server": "nginx"}, "clean"), "toxicache")
    assert miss is False
    assert empty == []


@pytest.mark.unit
def test_wcp_constants_are_non_empty_and_unique() -> None:
    assert len(CACHE_HEADERS) >= 10
    assert len(set(CACHE_HEADERS)) == len(CACHE_HEADERS)
    assert "x-cache" in CACHE_HEADERS
    assert len(WCP_HEADERS) >= 10
    assert "X-Forwarded-Host" in WCP_HEADERS
    assert WCP_PAYLOADS
    assert all(p.islower() for p in WCP_PAYLOADS)
