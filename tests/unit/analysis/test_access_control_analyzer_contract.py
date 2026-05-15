import asyncio

import pytest

from src.analysis.automation.access_control import AccessControlAnalyzer
from src.analysis.checks.active.access_control_analyzer import (
    analyze_access_control,
    analyze_access_control_async,
)


class _SyncResponseClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, str]]] = []

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
    ) -> dict[str, object]:
        _ = body
        self.calls.append((url, method, dict(headers or {})))
        return {
            "status_code": 200,
            "body_text": "ok",
            "headers": {},
        }


def _sample_endpoint() -> dict[str, object]:
    return {
        "url": "https://api.example.com/account",
        "method": "GET",
        "response": {"status_code": 200, "body": "ok"},
        "request_headers": {"Authorization": "Bearer original"},
    }


def test_check_endpoints_supports_sync_response_client() -> None:
    client = _SyncResponseClient()
    analyzer = AccessControlAnalyzer(http_client=client)

    results = analyzer.check_endpoints([_sample_endpoint()])

    assert len(results) == 2
    assert len(client.calls) == 2
    assert all(item.endpoint == "https://api.example.com/account" for item in results)


def test_analyze_endpoints_async_path_supports_sync_request_client() -> None:
    client = _SyncResponseClient()
    analyzer = AccessControlAnalyzer(http_client=client)

    results = asyncio.run(analyzer.analyze_endpoints([_sample_endpoint()]))

    assert len(results) == 2
    assert len(client.calls) == 2


@pytest.mark.asyncio
async def test_check_endpoints_rejects_running_event_loop() -> None:
    client = _SyncResponseClient()
    analyzer = AccessControlAnalyzer(http_client=client)

    with pytest.raises(
        RuntimeError, match="check_endpoints cannot be called from a running event loop"
    ):
        analyzer.check_endpoints([_sample_endpoint()])


@pytest.mark.asyncio
async def test_analyze_access_control_async_works_inside_running_loop() -> None:
    client = _SyncResponseClient()

    findings = await analyze_access_control_async(
        [_sample_endpoint()],
        response_cache=client,
        limit=10,
    )

    assert findings
    assert all(item["url"] == "https://api.example.com/account" for item in findings)


@pytest.mark.asyncio
async def test_sync_analyze_access_control_wrapper_rejects_running_event_loop() -> None:
    client = _SyncResponseClient()

    with pytest.raises(
        RuntimeError, match="analyze_access_control cannot be called from a running event loop"
    ):
        analyze_access_control([_sample_endpoint()], response_cache=client)
