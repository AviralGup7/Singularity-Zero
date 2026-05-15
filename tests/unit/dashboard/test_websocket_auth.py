from typing import Any, cast

import pytest

from src.websocket_server.auth import AuthenticationError, authenticate_websocket


class _Client:
    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host


class _FakeWebSocket:
    def __init__(
        self,
        *,
        query_params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        host: str = "127.0.0.1",
    ) -> None:
        self.query_params = query_params or {}
        self.headers = headers or {}
        self.client = _Client(host=host)


@pytest.mark.asyncio
async def test_authenticate_websocket_allows_anonymous_when_unconfigured() -> None:
    websocket = _FakeWebSocket()

    creds = await authenticate_websocket(
        websocket=cast(Any, websocket),
        jwt_secret=None,
        api_keys=None,
    )

    assert creds.auth_method == "none"
    assert creds.user_id.startswith("anonymous:")
    assert "anonymous" in creds.roles


@pytest.mark.asyncio
async def test_authenticate_websocket_rejects_missing_credentials_when_configured() -> None:
    websocket = _FakeWebSocket()

    with pytest.raises(AuthenticationError) as exc_info:
        await authenticate_websocket(
            websocket=cast(Any, websocket),
            jwt_secret="configured-secret",
            api_keys=None,
        )

    assert exc_info.value.code == "auth_missing_credentials"


@pytest.mark.asyncio
async def test_authenticate_websocket_accepts_api_key_query_param() -> None:
    websocket = _FakeWebSocket(query_params={"api_key": "admin-key"})

    creds = await authenticate_websocket(
        websocket=cast(Any, websocket),
        jwt_secret=None,
        api_keys={"admin-key": "admin-user"},
    )

    assert creds.auth_method == "api_key"
    assert creds.user_id == "admin-user"
