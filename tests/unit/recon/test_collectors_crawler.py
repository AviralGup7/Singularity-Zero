from src.recon.collectors import crawler


class _MockResp:
    def __init__(self, text: str, status_code: int = 200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"content-type": "text/html"}


def test_crawler_collects_anchor_and_script(monkeypatch):
    html = """
    <html>
      <body>
        <a href="/foo">link</a>
        <script src="/assets/app.js"></script>
      </body>
    </html>
    """

    def fake_get(url, timeout=None, allow_redirects=None, headers=None):
        assert "example.com" in url
        return _MockResp(html)

    monkeypatch.setattr("requests.get", fake_get)

    urls, meta = crawler.crawl_hosts(
        ["https://example.com/"],
        scope_entries=["example.com"],
        timeout_seconds=2,
        max_pages_per_host=10,
        workers=1,
    )

    assert any(u.endswith("/foo") for u in urls)
    assert any("/assets/app.js" in u for u in urls)
    assert meta["status"] == "ok"


def test_crawler_basic_js_and_links(monkeypatch):
    html = """
    <html>
      <head>
        <script src="/static/app.js"></script>
      </head>
      <body>
        <a href="/admin">Admin</a>
        <a href="/api/status">Status</a>
      </body>
    </html>
    """

    js = "const endpoint = '/api/v1/users?id=1';"

    def fake_get(url, params=None, timeout=None, headers=None):
        if url.endswith("app.js") or "app.js" in url:
            return _MockResp(js, headers={"content-type": "application/javascript"})
        return _MockResp(html)

    monkeypatch.setattr("requests.get", fake_get)

    urls, meta = crawler.crawl_hosts(
        ["https://app.example.com"],
        scope_entries=["app.example.com"],
        timeout_seconds=2,
        max_pages_per_host=3,
        workers=1,
        js_discovery=True,
    )

    assert "https://app.example.com/admin" in urls
    assert "https://app.example.com/api/status" in urls
    assert any("/api/v1/users" in u for u in urls)
    assert meta["status"] == "ok"
