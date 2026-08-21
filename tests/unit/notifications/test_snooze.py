from __future__ import annotations

from src.notifications import Inbox, from_finding
from src.notifications.snooze import SnoozeBook


def test_snooze_hides_until_deadline() -> None:
    inbox = Inbox()
    note = inbox.push(from_finding(finding_id="f", title="x", severity="low"))
    book = SnoozeBook()
    book.snooze(note.notification_id, 30, now=100.0)
    assert book.hidden(note.notification_id, now=110.0)
    assert not book.hidden(note.notification_id, now=140.0)
