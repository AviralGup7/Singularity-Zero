from __future__ import annotations

from src.auth import demo_session, jwt_session
from src.notifications import (
    Inbox,
    NotificationPriority,
    build_digest,
    from_finding,
    from_job_status,
    route_for,
    should_fetch,
)


def test_inbox_push_read_digest() -> None:
    inbox = Inbox()
    note = from_job_status("abc", "failed", message="boom")
    assert note is not None
    inbox.push(note)
    inbox.push(from_finding(finding_id="f1", title="SQLi", severity="critical"))
    assert inbox.unread_count() == 2
    inbox.mark_all_read()
    assert inbox.unread_count() == 0
    digest = build_digest(inbox)
    assert digest.total == 2
    assert should_fetch(demo_session()) is False
    assert should_fetch(jwt_session("n", "analyst", "tok")) is True


def test_critical_routes_to_email() -> None:
    note = from_finding(finding_id="f2", title="RCE", severity="critical")
    route = route_for(note)
    assert route.email is True
    assert note.priority is NotificationPriority.CRITICAL
