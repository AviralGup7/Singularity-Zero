"""Default API-key checklist is GET-only, host-scoped, and not 200-as-risk."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch
from urllib.parse import urlparse

from src.api_tests.apitester.api_key_checklist import (
    _probe_allowed_host,
    _request,
    run_api_key_checklist,
)

SECRET = "supersecretkeyvalue99"
SOURCE_HOST = "api.example.com"
SOURCE_URL = f"https://{SOURCE_HOST}/app.js?api_key={SECRET}"


class FakeResponse:
    def __init__(self, status_code: int, url: str, text: str = "ok") -> None:
        self.status_code = status_code
        self.url = url
        self.text = text
        self.headers = {"content-type": "text/plain"}


class FakeSession:
    def __init__(self, handler: Any) -> None:
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        timeout: int = 10,
        proxies: dict[str, str] | None = None,
        json: Any = None,
        allow_redirects: bool = True,
    ) -> FakeResponse:
        record = {
            "method": str(method or "").upper(),
            "url": url,
            "headers": dict(headers or {}),
            "params": dict(params or {}),
            "json": json,
        }
        self.calls.append(record)
        return self.handler(record)

    def close(self) -> None:
        return None


class FakeRequests:
    def __init__(self, handler: Any) -> None:
        self._handler = handler
        self.session: FakeSession | None = None

    def Session(self) -> FakeSession:  # noqa: N802
        self.session = FakeSession(self._handler)
        return self.session


def _always_200(record: dict[str, Any]) -> FakeResponse:
    return FakeResponse(200, record["url"])


def _auth_differential(record: dict[str, Any]) -> FakeResponse:
    headers = record["headers"]
    params = record["params"]
    blob = " ".join([*headers.values(), *params.values()])
    return FakeResponse(200 if SECRET in blob else 401, record["url"])


def _run(handler: Any, **kwargs: Any) -> tuple[dict[str, Any], FakeRequests]:
    requests_module = FakeRequests(handler)
    with patch("src.api_tests.apitester.api_key_checklist.time.sleep", return_value=None):
        payload = run_api_key_checklist(
            [SOURCE_URL],
            [],
            requests_module=requests_module,
            timeout=1,
            candidate_limit=1,
            **kwargs,
        )
    return payload, requests_module


def test_default_validation_sends_no_write_requests() -> None:
    _payload, requests_module = _run(_always_200)
    assert requests_module.session is not None
    methods = {call["method"] for call in requests_module.session.calls}
    assert methods == {"GET"}
    write_check = next(
        item for item in _payload["results"][0]["checks"] if item["id"] == "write_actions"
    )
    assert write_check["outcome"] == "info"
    assert "Skipped" in write_check["summary"]


def test_probes_stay_on_candidate_source_host() -> None:
    _payload, requests_module = _run(_always_200)
    assert requests_module.session is not None
    hosts = {urlparse(call["url"]).netloc.lower() for call in requests_module.session.calls}
    assert hosts == {SOURCE_HOST}

    token = _probe_allowed_host.set(SOURCE_HOST)
    try:
        blocked = _request(
            requests_module.session,
            "GET",
            "https://admin.example.com/users/me",
            headers={},
        )
    finally:
        _probe_allowed_host.reset(token)
    assert blocked["ok"] is False
    assert blocked["error"] == "host_not_allowed"
    assert all("admin.example.com" not in call["url"] for call in requests_module.session.calls)


def test_matching_200s_are_not_reported_as_risk() -> None:
    payload, _requests = _run(_always_200)
    checks = {item["id"]: item for item in payload["results"][0]["checks"]}
    assert checks["direct_no_login"]["outcome"] == "ok"
    assert checks["key_alone"]["outcome"] == "ok"
    assert payload["results"][0]["totals"]["risk_count"] == 0


def test_auth_differential_200_vs_401_is_risk() -> None:
    payload, _requests = _run(_auth_differential)
    checks = {item["id"]: item for item in payload["results"][0]["checks"]}
    assert checks["direct_no_login"]["outcome"] == "risk"
    assert checks["key_alone"]["outcome"] == "risk"


def test_checklist_results_never_include_raw_key() -> None:
    payload, _requests = _run(_always_200)
    dumped = repr(payload)
    assert SECRET not in dumped
    assert payload["results"][0]["candidate"]["masked_key"]
    assert SECRET not in payload["results"][0]["candidate"]["masked_key"]
    assert SECRET not in payload["results"][0]["candidate"]["source_url"]


def test_write_probes_only_when_explicitly_enabled() -> None:
    _payload, requests_module = _run(_always_200, allow_write_probes=True)
    assert requests_module.session is not None
    methods = {call["method"] for call in requests_module.session.calls}
    assert {"POST", "PUT", "DELETE"} <= methods
