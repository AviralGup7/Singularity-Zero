from __future__ import annotations

from tests.test_support.journal import MemoryJournal

from src.frontier.deltas import delta


def test_memory_journal_replay() -> None:
    journal = MemoryJournal()
    journal.append(delta(urls=["https://a.test/"], wal_id="1-0"))
    journal.append(delta(urls=["https://b.test/"], wal_id="2-0"))
    counts = journal.replay()
    assert counts["urls"] >= 1
    assert len(journal) == 2
