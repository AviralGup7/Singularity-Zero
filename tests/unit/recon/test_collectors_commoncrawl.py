import json

from src.recon.collectors.providers import commoncrawl


class _MockResp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": "application/json"}


def test_parse_ndjson_shape(monkeypatch):
    # NDJSON: each line is a JSON object with 'url'
    lines = [
        json.dumps({"url": "http://example.com/"}),
        json.dumps({"url": "http://example.com/page"}),
    ]
    payload = "\n".join(lines) + "\n"

    def fake_get(url, params=None, timeout=None):
        assert "commoncrawl" in url or "index.commoncrawl" in url
        return _MockResp(payload)

    monkeypatch.setattr("requests.get", fake_get)

    urls, meta = commoncrawl.collect_for_hosts(
        ["example.com"], timeout_seconds=5, per_host_limit=10, max_workers=2
    )

    assert "http://example.com" in urls
    assert "http://example.com/page" in urls
    assert meta["status"] == "ok"


def test_parse_plain_lines(monkeypatch):
    payload = "http://example.com/\nhttp://example.com/foo\n"

    def fake_get(url, params=None, timeout=None):
        return _MockResp(payload)

    monkeypatch.setattr("requests.get", fake_get)

    urls, meta = commoncrawl.collect_for_hosts(
        ["example.com"], timeout_seconds=5, per_host_limit=10, max_workers=1
    )

    assert "http://example.com" in urls
    assert any(u.endswith("/foo") for u in urls)
    assert meta["status"] == "ok"
