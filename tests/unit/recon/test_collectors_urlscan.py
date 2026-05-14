import json

from src.recon.collectors.providers import urlscan


class _MockResp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": "application/json"}


def test_parse_urlscan_json_array_shape(monkeypatch):
    payload = json.dumps(
        {
            "results": [
                {"page": {"url": "http://example.com/"}},
                {"page": {"url": "http://example.com/foo"}},
            ]
        }
    )

    def fake_get(url, params=None, timeout=None):
        assert "urlscan" in url
        return _MockResp(payload)

    monkeypatch.setattr("requests.get", fake_get)

    urls, meta = urlscan.collect_for_hosts(
        ["example.com"], timeout_seconds=5, per_host_limit=10, max_workers=1
    )

    assert "http://example.com" in urls
    assert any(u.endswith("/foo") for u in urls)
    assert meta["status"] == "ok"
