"""Tests for Kuzu Cypher query parameterization (Cypher injection defence)."""

from unittest.mock import MagicMock, patch

import pytest

from src.analysis.intelligence import lateral_graph
from src.analysis.intelligence.lateral_graph import (
    LateralGraph,
    _safe_identifier,
    _safe_severity,
    insert_relationship,
    upsert_node,
)


class FakeKuzuConn:
    """Minimal in-memory fake of a kuzu connection for query assertions."""

    def __init__(self):
        self.executed: list[tuple[str, dict]] = []
        self.query_result = MagicMock()
        self.query_result.has_next.return_value = False
        self.query_result.get_next.return_value = None

    def execute(self, query, parameters=None):
        self.executed.append((query, parameters or {}))
        return self.query_result


def test_safe_identifier_accepts_alnum_and_underscore():
    assert _safe_identifier("Host_42") == "Host_42"


@pytest.mark.parametrize(
    "bad",
    [
        "Host;DROP",
        "Host'",
        "Host\"",
        "Host n match",
        "Host\nname",
        "Host--comment",
        "1Host",  # leading digit
        "",
        "host{}",
    ],
)
def test_safe_identifier_rejects_injection(bad: str):
    with pytest.raises(ValueError):
        _safe_identifier(bad)


def test_safe_severity_only_allows_known_levels():
    for sev in ("low", "medium", "high", "critical", "info"):
        assert _safe_severity(sev) == sev


@pytest.mark.parametrize("bad", ["HIGH'; DROP", "ultrahigh", "lo", "🟥", ""])
def test_safe_severity_rejects_unknown(bad: str):
    with pytest.raises(ValueError):
        _safe_severity(bad)


def test_upsert_node_uses_parameterized_query():
    conn = FakeKuzuConn()
    with patch.object(lateral_graph, "_get_connection", return_value=conn):
        LateralGraph(db_path=":memory:").upsert_node(
            label="Host",
            key="h1",
            properties={"ip": "10.0.0.1", "os": "linux"},
        )
    assert len(conn.executed) == 1
    query, params = conn.executed[0]
    # The query must use $param placeholders, not f-string interpolation
    assert "$label" in query
    assert "$key" in query
    assert params["label"] == "Host"
    assert params["key"] == "h1"
    # The user-supplied property values must NOT be string-formatted into the query
    assert "10.0.0.1" not in query
    assert "linux" not in query


def test_upsert_node_rejects_unsafe_label():
    g = LateralGraph(db_path=":memory:")
    with pytest.raises(ValueError):
        g.upsert_node(label="Host; DROP TABLE Host", key="h1", properties={})


def test_upsert_node_rejects_unsafe_key():
    g = LateralGraph(db_path=":memory:")
    with pytest.raises(ValueError):
        g.upsert_node(label="Host", key="h1' OR 1=1 --", properties={})


def test_insert_relationship_uses_parameterized_query():
    conn = FakeKuzuConn()
    with patch.object(lateral_graph, "_get_connection", return_value=conn):
        LateralGraph(db_path=":memory:").insert_relationship(
            src_label="Host",
            src_key="h1",
            rel_type="CONNECTED_TO",
            dst_label="Service",
            dst_key="s1",
            severity="high",
        )
    query, params = conn.executed[0]
    assert "$rel_type" in query
    assert params["rel_type"] == "CONNECTED_TO"
    assert params["severity"] == "high"


def test_insert_relationship_rejects_unsafe_rel_type():
    g = LateralGraph(db_path=":memory:")
    with pytest.raises(ValueError):
        g.insert_relationship(
            src_label="Host",
            src_key="h1",
            rel_type="EXPLOITED' OR 1=1 --",
            dst_label="Service",
            dst_key="s1",
            severity="high",
        )


def test_insert_relationship_rejects_unsafe_severity():
    g = LateralGraph(db_path=":memory:")
    with pytest.raises(ValueError):
        g.insert_relationship(
            src_label="Host",
            src_key="h1",
            rel_type="CONNECTED_TO",
            dst_label="Service",
            dst_key="s1",
            severity="HIGHEST'; DROP",
        )


def test_legacy_cypher_string_is_a_shim():
    """The legacy helper must not actually be used to build queries; it
    only escapes values for backward-compat callers."""
    from src.analysis.intelligence.lateral_graph import _cypher_string
    result = _cypher_string("normal value")
    assert isinstance(result, str)
    # And it should escape quotes in the input
    escaped = _cypher_string("a'b")
    assert "\\'" in escaped or "''" in escaped
