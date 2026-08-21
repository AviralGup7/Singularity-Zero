from __future__ import annotations

from src.frontier.deltas import apply_many, delta, finding_titles, snapshot_counts
from src.frontier.verify import cursor_not_before, replay_gap, snapshot_sane


def test_apply_deltas_and_counts() -> None:
    payloads = [
        delta(subdomains=["a.example"], urls=["https://a.example/"], wal_id="1-1"),
        delta(findings=[{"id": "f1", "title": "SQLi"}], wal_id="1-2"),
    ]
    state = apply_many(payloads)
    counts = snapshot_counts(state)
    assert counts["subdomains"] == 1
    assert counts["urls"] == 1
    assert counts["findings"] == 1
    assert "SQLi" in finding_titles(state)


def test_snapshot_and_cursor() -> None:
    assert snapshot_sane({"format": "neural-state-crdt-v3", "sets": {}})
    assert snapshot_sane({"subdomains": []})
    assert snapshot_sane(None) is False
    assert cursor_not_before("2-0", "1-0") is True
    assert replay_gap("2-0", ["1-0", "2-0", "3-0"]) == ["1-0", "2-0"]
