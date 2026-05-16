"""Runner for crawler unit test without pytest/coverage hooks.

This loader avoids importing the package top-level `src.recon` which
may execute other modules; instead it dynamically loads the modules
we need by file path and injects them into `sys.modules`.
"""

import importlib.util
import os
import sys


from typing import Any, cast


def _load_module(name: str, path: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Failed to load module {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _run() -> None:
    root = os.path.dirname(os.path.dirname(__file__))
    src_root = os.path.join(root, "src")

    # load minimal dependencies into sys.modules under expected names
    _load_module("src.recon.common", os.path.join(src_root, "recon", "common.py"))
    _load_module(
        "src.recon.collectors.observability",
        os.path.join(src_root, "recon", "collectors", "observability.py"),
    )
    _load_module(
        "src.recon.collectors.metrics", os.path.join(src_root, "recon", "collectors", "metrics.py")
    )

    # load the crawler module
    crawler = _load_module(
        "src.recon.collectors.crawler", os.path.join(src_root, "recon", "collectors", "crawler.py")
    )

    class _MockResp:
        def __init__(self, text: str, status_code: int = 200, headers: dict[str, str] | None = None) -> None:
            self.text = text
            self.status_code = status_code
            self.headers = headers or {"content-type": "text/html"}

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

    def fake_get(url: str, params: Any = None, timeout: Any = None, headers: Any = None, **kwargs: Any) -> Any:
        if url.endswith("app.js") or "app.js" in url:
            return _MockResp(js, headers={"content-type": "application/javascript"})
        return _MockResp(html)

    import requests

    orig = requests.get
    requests.get = cast(Any, fake_get)
    try:
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
    finally:
        requests.get = orig

    print("CRAWLER TESTS PASSED")


if __name__ == "__main__":
    _run()
