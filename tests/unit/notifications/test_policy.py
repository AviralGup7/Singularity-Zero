from __future__ import annotations

from src.auth import demo_session, jwt_session
from src.notifications import should_fetch, should_open_stream


def test_demo_session_does_not_fetch_inbox() -> None:
    assert should_fetch(demo_session()) is False
    assert should_open_stream(demo_session()) is False


def test_explicit_bearer_overrides_demo() -> None:
    assert should_fetch(demo_session(), bearer_token="jwt") is True


def test_jwt_session_fetches() -> None:
    session = jwt_session("n", "analyst", token="jwt")
    assert should_fetch(session) is True


def test_missing_session_does_not_fetch() -> None:
    assert should_fetch(None) is False
