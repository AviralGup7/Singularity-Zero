import logging

from src.detection.signals import compose_signals


def test_compose_signals_basic():
    assert compose_signals("foo", "bar") == ["bar", "foo"]
    assert compose_signals("  foo  ", "bar") == ["bar", "foo"]


def test_compose_signals_collections():
    assert compose_signals(["foo", "bar"], ("baz",)) == ["bar", "baz", "foo"]
    assert compose_signals({"foo"}, ["bar"]) == ["bar", "foo"]


def test_compose_signals_deduplication():
    assert compose_signals("foo", ["foo", "bar"], "bar") == ["bar", "foo"]


def test_compose_signals_none_handling(caplog):
    with caplog.at_level(logging.WARNING):
        res = compose_signals(None, "foo", [None, "bar"])
    assert res == ["bar", "foo"]
    assert any("Received None value directly" in record.message for record in caplog.records)
    assert any("Received None value nested inside" in record.message for record in caplog.records)
