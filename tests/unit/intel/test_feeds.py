from __future__ import annotations

from src.intel import configured_feed_keys, is_feed_configured, list_feeds


def test_list_feeds_includes_vt_and_otx() -> None:
    keys = {feed.key for feed in list_feeds()}
    assert {"virustotal", "otx", "misp", "shodan"}.issubset(keys)


def test_unconfigured_by_default(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    for feed in list_feeds():
        monkeypatch.delenv(feed.env_var, raising=False)
    assert configured_feed_keys() == ()
    assert is_feed_configured("virustotal") is False


def test_configured_when_env_present(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("VT_API_KEY", "vt-test")
    assert is_feed_configured("virustotal") is True
    assert "virustotal" in configured_feed_keys()
