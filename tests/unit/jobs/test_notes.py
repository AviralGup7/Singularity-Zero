from __future__ import annotations

from src.jobs.notes import JobNotes


def test_notes_per_job() -> None:
    notes = JobNotes()
    notes.add("j1", "ada", "looks stalled")
    notes.add("j2", "ada", "ok")
    assert len(notes.for_job("j1")) == 1
    assert len(notes) == 2
