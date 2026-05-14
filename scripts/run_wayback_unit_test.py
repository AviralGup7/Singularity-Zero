"""Simple runner to exercise the Wayback provider tests without pytest.

This script is intentionally minimal: it mocks `requests.get` and runs
the same assertions used in the pytest unit tests so CI-style coverage
doesn't run across the entire repository while we iterate locally.
"""

import json
import sys

from src.recon.collectors.providers import commoncrawl, wayback


class _MockResp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": "application/json"}


def _test_parse_cdx_json_array_shape():
    payload = json.dumps([["original"], ["http://example.com/"], ["http://example.com/page"]])

    def fake_get(url, params=None, timeout=None):
        return _MockResp(payload)

    # Monkeypatch requests.get in the requests module used by wayback
    import requests

    orig = requests.get
    requests.get = fake_get
    try:
        urls, meta = wayback.collect_for_hosts(
            ["example.com"], timeout_seconds=5, per_host_limit=10, max_workers=2
        )
        assert "http://example.com" in urls
        assert "http://example.com/page" in urls
        assert meta["status"] == "ok"
    finally:
        requests.get = orig


def _test_parse_cdx_plain_lines():
    payload = "http://example.com/\nhttp://example.com/foo\n"

    def fake_get(url, params=None, timeout=None):
        return _MockResp(payload)

    import requests

    orig = requests.get
    requests.get = fake_get
    try:
        urls, meta = wayback.collect_for_hosts(
            ["example.com"], timeout_seconds=5, per_host_limit=10, max_workers=1
        )
        assert "http://example.com" in urls
        assert any(u.endswith("/foo") for u in urls)
        assert meta["status"] == "ok"
    finally:
        requests.get = orig


def main():
    _test_parse_cdx_json_array_shape()
    _test_parse_cdx_plain_lines()

    # CommonCrawl tests
    def _test_cc_ndjson_shape():
        lines = [
            json.dumps({"url": "http://example.com/"}),
            json.dumps({"url": "http://example.com/page"}),
        ]
        payload = "\n".join(lines) + "\n"

        def fake_get(url, params=None, timeout=None):
            return _MockResp(payload)

        import requests

        orig = requests.get
        requests.get = fake_get
        try:
            urls, meta = commoncrawl.collect_for_hosts(
                ["example.com"], timeout_seconds=5, per_host_limit=10, max_workers=2
            )
            assert "http://example.com" in urls
            assert "http://example.com/page" in urls
            assert meta["status"] == "ok"
        finally:
            requests.get = orig

    def _test_cc_plain_lines():
        payload = "http://example.com/\nhttp://example.com/foo\n"

        def fake_get(url, params=None, timeout=None):
            return _MockResp(payload)

        import requests

        orig = requests.get
        requests.get = fake_get
        try:
            urls, meta = commoncrawl.collect_for_hosts(
                ["example.com"], timeout_seconds=5, per_host_limit=10, max_workers=1
            )
            assert "http://example.com" in urls
            assert any(u.endswith("/foo") for u in urls)
            assert meta["status"] == "ok"
        finally:
            requests.get = orig

    _test_cc_ndjson_shape()
    _test_cc_plain_lines()
    print("COLLECTORS (Wayback + CommonCrawl) TESTS PASSED")
    print("WAYBACK PROVIDER TESTS PASSED")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print("Tests failed:", exc)
        sys.exit(2)
