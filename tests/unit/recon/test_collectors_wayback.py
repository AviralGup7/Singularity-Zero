import json

from src.recon.collectors.providers import wayback


class _MockResp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": "application/json"}


def test_parse_cdx_json_array_shape(monkeypatch):
    # Simulate CDX JSON array-of-arrays with header
    payload = json.dumps([["original"], ["http://example.com/"], ["http://example.com/page"]])

    def fake_get(url, params=None, timeout=None):
        assert "cdx" in url
        return _MockResp(payload)

    monkeypatch.setattr("requests.get", fake_get)

    urls, meta = wayback.collect_for_hosts(
        ["example.com"], timeout_seconds=5, per_host_limit=10, max_workers=2
    )

    # normalize_url strips trailing slashes, assert normalized forms
    assert "http://example.com" in urls
    assert "http://example.com/page" in urls
    assert meta["status"] == "ok"


def test_parse_cdx_plain_lines(monkeypatch):
    # Simulate plain-line response
    payload = "http://example.com/\nhttp://example.com/foo\n"

    def fake_get(url, params=None, timeout=None):
        return _MockResp(payload)

    monkeypatch.setattr("requests.get", fake_get)

    urls, meta = wayback.collect_for_hosts(
        ["example.com"], timeout_seconds=5, per_host_limit=10, max_workers=1
    )

    assert "http://example.com" in urls
    assert any(u.endswith("/foo") for u in urls)
    assert meta["status"] == "ok"
