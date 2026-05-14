import json

from src.recon.collectors.providers import otx


class _MockResp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": "application/json"}


def test_parse_otx_json(monkeypatch):
    payload = json.dumps(
        {"url_list": [{"url": "http://example.com/"}, {"url": "http://example.com/bar"}]}
    )

    def fake_get(url, headers=None, timeout=None):
        return _MockResp(payload)

    monkeypatch.setattr("requests.get", fake_get)

    urls, meta = otx.collect_for_hosts(
        ["example.com"], timeout_seconds=5, per_host_limit=10, max_workers=1
    )

    assert "http://example.com" in urls
    assert any(u.endswith("/bar") for u in urls)
    assert meta["status"] == "ok"
