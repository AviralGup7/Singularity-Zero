from __future__ import annotations

from src.frontier.deltas import delta
from src.frontier.journal import MemoryJournal


def test_memory_journal_replay() -> None:
    journal = MemoryJournal()
    journal.append(delta(urls=["https://a.test/"], wal_id="1-0"))
    journal.append(delta(urls=["https://b.test/"], wal_id="2-0"))
    counts = journal.replay()
    assert counts["urls"] >= 1
    assert len(journal) == 2
