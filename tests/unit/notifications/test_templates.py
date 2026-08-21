from __future__ import annotations

from src.notifications.inbox import Inbox
from src.notifications.templates import job_completed, job_failed, self_healing, stage_failed


def test_templates_land_in_inbox() -> None:
    inbox = Inbox()
    inbox.push(job_completed("j1", "app.test", 3))
    inbox.push(job_failed("j1", "app.test", "nuclei crashed"))
    inbox.push(stage_failed("j1", "nuclei", "timeout"))
    inbox.push(self_healing("open_breaker", "nuclei", "too many 429s"))
    assert len(inbox) == 4
    assert inbox.high_priority()
