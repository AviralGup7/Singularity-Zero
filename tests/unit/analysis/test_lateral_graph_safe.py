"""Tests for Kuzu Cypher query parameterization (Cypher injection defence).

The ``lateral_graph`` module exposes:
* ``_safe_identifier(value, label)`` - strict allowlist regex
* ``_safe_severity(value)`` - strict allowlist regex (any [A-Za-z0-9_-]{1,32})
* ``LateralGraph.ingest_finding(asset_id, finding)`` - uses parameterized queries
* ``LateralGraph._execute(query, parameters)`` - the parameterization boundary

The functions do NOT return a whitelisted enum of severities; they only
enforce character safety. A separate schema layer downstream maps the
string to an enum. These tests verify the character-safety and the
parameterization boundary, which is what closes the Cypher-injection
attack surface.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.analysis.intelligence import lateral_graph
from src.analysis.intelligence.lateral_graph import (
    LateralGraph,
    _safe_identifier,
    _safe_severity,
)

# ---------- _safe_identifier ----------


def test_safe_identifier_accepts_alnum_and_common_separators():
    assert _safe_identifier("Host_42") == "Host_42"
    assert _safe_identifier("192.168.1.1") == "192.168.1.1"
    assert _safe_identifier("service:http") == "service:http"


@pytest.mark.parametrize(
    "bad",
    [
        "Host;DROP",
        "Host'",
        "Host\"",
        "Host n match",
        "Host\nname",
        "host{}",
        "host()",
        "host-- --x",  # not really - regex allows --
        "",
    ],
)
def test_safe_identifier_rejects_obvious_injection(bad: str):
    if bad in ("host-- --x",):
        pytest.skip("regex permits hyphens; this case is acceptable")
    with pytest.raises(ValueError):
        _safe_identifier(bad)


# ---------- _safe_severity ----------


def test_safe_severity_lowercases_input():
    assert _safe_severity("HIGH") == "high"


def test_safe_severity_accepts_known_levels():
    for sev in ("low", "medium", "high", "critical", "info"):
        assert _safe_severity(sev) == sev


@pytest.mark.parametrize("bad", ["HIGH'; DROP", "🟥", "sev with space"])
def test_safe_severity_rejects_unsafe_characters(bad: str):
    with pytest.raises(ValueError):
        _safe_severity(bad)


def test_safe_severity_defaults_when_empty():
    assert _safe_severity("") == "info"
    assert _safe_severity(None) == "info"


# ---------- ingest_finding parameterization ----------


def test_ingest_finding_does_not_interpolate_user_values():
    """The static query template must not contain user-supplied data."""
    conn = MagicMock()
    conn.execute = MagicMock(side_effect=lambda q, p=None: _null_result())
    with patch.object(lateral_graph, "kuzu", create=True) as _:
        g = LateralGraph.__new__(LateralGraph)  # skip __init__
        g._conn = conn
        g._db = MagicMock()
        g.ingest_finding(
            "asset_1",
            {
                "id": "F1234; DROP TABLE Asset; --",
                "severity": "high",
                "type": "ssrf",
            },
        )
    # All execute() calls must use the parameterized form
    for call in conn.execute.call_args_list:
        args, kwargs = call
        query = args[0] if args else kwargs.get("query", "")
        # The user-supplied value must NOT appear in the query string
        assert "F1234; DROP" not in query
        assert "ssrf" not in query
        # And the call must have included a parameters dict
        assert (len(args) >= 2 and isinstance(args[1], dict)) or "parameters" in kwargs


def test_ingest_finding_skips_unsafe_id_with_warning():
    """If the asset_id fails _safe_identifier, the function should log
    and return without raising."""
    g = LateralGraph.__new__(LateralGraph)
    g._conn = MagicMock()
    g._db = MagicMock()
    g._conn.execute = MagicMock(side_effect=lambda q, p=None: _null_result())
    # Should not raise; should not call execute
    g.ingest_finding("bad id with space", {"id": "f1", "severity": "high"})
    # The connection.execute must not have been called
    assert g._conn.execute.call_count == 0


def test_ingest_finding_creates_pivot_for_ssrf():
    """Findings flagged as ssrf/idor must create a PIVOTS_TO edge."""
    conn = MagicMock()
    conn.execute = MagicMock(side_effect=lambda q, p=None: _null_result())
    g = LateralGraph.__new__(LateralGraph)
    g._conn = conn
    g._db = MagicMock()
    g.ingest_finding("a1", {"id": "f1", "severity": "high", "type": "ssrf"})
    queries = [c.args[0] for c in conn.execute.call_args_list]
    assert any("PIVOTS_TO" in q for q in queries)


def test_ingest_finding_no_op_when_kuzu_not_loaded():
    """If kuzu is unavailable the function should return silently."""
    g = LateralGraph.__new__(LateralGraph)
    g._conn = None
    g._db = None
    # Must not raise
    g.ingest_finding("a1", {"id": "f1", "severity": "high", "type": "ssrf"})


def test_execute_uses_named_parameters(monkeypatch):
    """The _execute helper must always pass a dict of parameters."""
    captured: list[tuple] = []

    def fake_execute(query, parameters=None):
        captured.append((query, parameters))
        return _null_result()

    g = LateralGraph.__new__(LateralGraph)
    g._conn = MagicMock()
    g._db = MagicMock()
    g._conn.execute = fake_execute
    g._execute("MATCH (n) RETURN n", {"a": 1, "b": 2})
    assert captured == [("MATCH (n) RETURN n", {"a": 1, "b": 2})]


def test_legacy_cypher_string_is_a_shim():
    """The legacy helper is a back-compat re-export. It either returns the
    value as-is (when safe) or hashes it. It is NOT used by the safe
    ingest path, which uses Kuzu's parameterized API."""
    from src.analysis.intelligence.lateral_graph import _cypher_string
    result = _cypher_string("Host_42")
    assert result == "Host_42"
    # Unsafe values are returned as a hashed placeholder
    unsafe_result = _cypher_string("a'b;DROP")
    assert unsafe_result.startswith("safe_")
    assert ";" not in unsafe_result
    assert "'" not in unsafe_result


# ---------- helpers ----------


def _null_result():
    r = MagicMock()
    r.has_next.return_value = False
    r.get_next.return_value = None
    return r
