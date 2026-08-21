from __future__ import annotations

from src.intel.expand import expand
from src.intel.ioc import IndicatorKind


def test_expand_url_includes_domain() -> None:
    kinds = {item.kind for item in expand("https://evil.example.com/x")}
    assert IndicatorKind.URL in kinds
    assert IndicatorKind.DOMAIN in kinds
