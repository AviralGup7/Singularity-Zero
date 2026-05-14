import json

import requests

from src.recon.collectors.providers import wayback


class _MockResp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": "application/json"}


def test_retry_on_transient_error(monkeypatch):
    # First call raises, second returns valid payload
    payload = json.dumps([["original"], ["http://example.com/"], ["http://example.com/page"]])

    calls = {"n": 0}

    def fake_get(url, params=None, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise requests.RequestException("transient")
        return _MockResp(payload)

    monkeypatch.setattr("requests.get", fake_get)

    urls, meta = wayback.collect_for_hosts(
        ["example.com"], timeout_seconds=5, per_host_limit=10, max_workers=1
    )

    assert calls["n"] == 2
    assert meta["status"] == "ok"
    assert "http://example.com" in urls
