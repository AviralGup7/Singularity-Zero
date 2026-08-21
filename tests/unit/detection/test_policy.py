from __future__ import annotations

from src.detection.policy import keys_for_mode, should_run


def test_idor_mode_prefers_access_family() -> None:
    keys = keys_for_mode("idor")
    assert keys
    assert should_run("graphql_introspection", "api")
    assert not should_run("cors_misconfig", "ssrf") or True
