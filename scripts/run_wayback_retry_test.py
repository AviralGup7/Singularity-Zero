import json
import sys
from typing import Any, cast

import requests

from src.recon.collectors.providers import wayback


class _MockResp:
    def __init__(self, text: str, status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": "application/json"}


payload = json.dumps([["original"], ["http://example.com/"], ["http://example.com/page"]])

calls = {"n": 0}


def fake_get(url: str, params: Any = None, timeout: Any = None, **kwargs: Any) -> Any:
    calls["n"] += 1
    if calls["n"] == 1:
        raise requests.RequestException("transient")
    return _MockResp(payload)


# Monkeypatch requests.get
requests.get = cast(Any, fake_get)

urls, meta = wayback.collect_for_hosts(
    ["example.com"], timeout_seconds=5, per_host_limit=10, max_workers=1
)

print("calls=", calls["n"])
print("meta=", meta)
print("sample_urls=", list(urls)[:5])

sys.exit(0 if meta.get("status") == "ok" else 2)
