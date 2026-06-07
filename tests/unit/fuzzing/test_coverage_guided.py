import asyncio

import pytest

from src.fuzzing.coverage_guided import CorpusEntry, CorpusManager, CoverageTracker


def test_corpus_manager_add_and_select():
    corpus = CorpusManager(max_size=500)
    corpus.add("payload1", "sig1")
    corpus.add("payload2", "sig2")
    corpus.add("payload3", "sig3")
    energies = []
    for _ in range(6):
        entry = corpus.select_next()
        if entry is not None:
            energies.append(entry.energy)
    assert len([e for e in energies if e > 0]) <= 6


def test_corpus_manager_max_size():
    corpus = CorpusManager(max_size=500)
    for i in range(600):
        corpus.add(f"payload{i}", f"sig{i}")
    assert len(corpus.entries) <= 500


def test_coverage_tracker_new_edge():
    tracker = CoverageTracker()
    first = tracker.record_edge("http://example.com/api", 200, 450, "abcd1234")
    second = tracker.record_edge("http://example.com/api", 200, 450, "abcd1234")
    assert first != ""
    assert second == ""
    third = tracker.record_edge("http://example.com/api", 200, 550, "efgh5678")
    assert third != ""


def test_coverage_tracker_branch():
    tracker = CoverageTracker()
    first = tracker.record_branch("/api", "/login")
    second = tracker.record_branch("/api", "/login")
    assert first == second


def test_minimize_payload():
    entry = CorpusEntry(payload="hello world", signature="sig", energy=10)
    corpus = CorpusManager()
    minimized = corpus.minimize(entry)
    assert len(minimized.payload) <= len(entry.payload)
