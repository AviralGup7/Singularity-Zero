from __future__ import annotations

from src.auth.session import demo_session, jwt_session
from src.console.demo_channel import policy_payload, should_call_jwt_path, should_use_console_inbox
from src.integration.authz import jwt_notifications_allowed


def test_demo_uses_console_inbox_not_jwt() -> None:
    session = demo_session("Ada", "analyst")
    assert should_use_console_inbox(session) is True
    assert jwt_notifications_allowed(session) is False
    assert should_call_jwt_path("/api/notifications", session) is False
    assert should_call_jwt_path("/api/notifications/stream", session) is False
    policy = policy_payload(session)
    assert policy["skip_jwt_notifications"] is True
    assert policy["use_console_inbox"] is True
    assert policy["fetch_notifications_http"] is False


def test_jwt_uses_http_inbox() -> None:
    session = jwt_session("ada", "analyst", "tok-secret")
    assert should_use_console_inbox(session) is False
    assert jwt_notifications_allowed(session, bearer_token="tok-secret") is True
    assert should_call_jwt_path("/api/notifications", session, bearer_token="tok-secret") is True
    policy = policy_payload(session, bearer_token="tok-secret")
    assert policy["skip_jwt_notifications"] is False


def test_anonymous_skips_both() -> None:
    assert should_use_console_inbox(None) is False
    assert should_call_jwt_path("/api/notifications", None) is False
    assert should_call_jwt_path("/api/jobs", None) is True
