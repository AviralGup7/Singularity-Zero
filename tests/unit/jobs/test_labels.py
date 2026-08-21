from __future__ import annotations

from src.jobs.labels import findings_tone, progress_label, status_tone


def test_tones() -> None:
    assert status_tone("failed") == "bad"
    assert status_tone("completed") == "ok"
    assert findings_tone(0) == "ok"
    assert findings_tone(3, critical=1) == "bad"
    assert progress_label(0) == "queued"
    assert progress_label(100) == "done"
