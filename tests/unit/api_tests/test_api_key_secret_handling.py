"""API keys must never be returned in full from helpers or security results."""

from __future__ import annotations

from typing import Any

from src.api_tests.apitester import api_key_security as key_security
from src.api_tests.apitester.client import display_secret

SECRET = "shortkey12"
LONG_SECRET = "sk-live-super-secret-value-9999"


class FakeResponse:
    def __init__(self, url: str) -> None:
        self.status_code = 404
        self.url = url
        self.text = ""
        self.headers = {"content-type": "text/plain"}


class FakeSession:
    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        return FakeResponse(url)

    def close(self) -> None:
        return None


class FakeRequests:
    def Session(self) -> FakeSession:
        return FakeSession()


def test_display_secret_never_returns_full_key() -> None:
    assert display_secret("") == ""
    assert display_secret("abc") != "abc"
    assert display_secret("abcdefghijkl") != "abcdefghijkl"
    assert display_secret(SECRET) != SECRET
    assert display_secret(LONG_SECRET) != LONG_SECRET
    assert SECRET not in display_secret(SECRET)
    assert LONG_SECRET not in display_secret(LONG_SECRET)


def test_api_key_security_results_redact_raw_key() -> None:
    payload = key_security.test_api_key_security(
        "https://api.example.com",
        LONG_SECRET,
        requests_module=FakeRequests(),
        timeout=1,
        endpoints=["users/me"],
    )
    dumped = repr(payload)
    assert LONG_SECRET not in dumped
    for location in payload["results"]:
        assert LONG_SECRET not in repr(location["headers"])
        assert LONG_SECRET not in repr(location["params"])
