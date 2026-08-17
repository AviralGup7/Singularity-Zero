"""Coverage for streaming analysis context iterators."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.pipeline.parallel_analysis.streaming_context import StreamingAnalysisContext


@pytest.mark.unit
def test_iterators_prefer_direct_attributes() -> None:
    ctx = StreamingAnalysisContext(
        SimpleNamespace(
            live_hosts=["h1"],
            urls=["https://a.test/x"],
            subdomains=["a.test"],
        )
    )
    assert list(ctx.iter_live_hosts()) == ["h1"]
    assert list(ctx.iter_urls()) == ["https://a.test/x"]
    assert list(ctx.iter_subdomains()) == ["a.test"]


@pytest.mark.unit
def test_iterators_fall_back_to_result() -> None:
    ctx = StreamingAnalysisContext(
        SimpleNamespace(result=SimpleNamespace(live_hosts=["h2"], urls=["u2"], subdomains=["s2"]))
    )
    assert list(ctx.iter_live_hosts()) == ["h2"]
    assert list(ctx.iter_urls()) == ["u2"]
    assert list(ctx.iter_subdomains()) == ["s2"]
